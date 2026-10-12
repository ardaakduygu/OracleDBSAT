# run_assessment.py  (CLEAN, NO MOCK)
import sys
import os
from datetime import datetime
import oracledb
import mysql.connector
from dotenv import load_dotenv

load_dotenv()

# --- MySQL Configuration (Assessment Database) ---
DB_USER = os.getenv('DB_USER', 'app_user')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_NAME = os.getenv('DB_NAME', 'app_data')
if not DB_PASSWORD:
    raise RuntimeError('DB_PASSWORD must be set in .env or environment')
# -------------------------------------------------


def get_enabled_tests():
    """
    Connects to local MySQL and returns all tests with Status = 'Enable'.
    Returns: list[dict]
    """
    tests = []
    mydb = None
    cursor = None
    try:
        mydb = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        cursor = mydb.cursor(dictionary=True, buffered=True)
        query = """
            SELECT Id, Name, Severity, Description, SQL_Test, SQL_Detail, Text_Pass, Text_Fail
            FROM assessment_tests
            WHERE Status = 'Enable'
            ORDER BY Id ASC
        """
        cursor.execute(query)
        tests = cursor.fetchall()
        print(f"[INFO] Loaded {len(tests)} enabled tests from MySQL.")
        return tests
    except mysql.connector.Error as err:
        print(f"[ERROR] MySQL error in get_enabled_tests: {err}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] General error in get_enabled_tests: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        if cursor:
            cursor.close()
        if mydb and mydb.is_connected():
            mydb.close()


def format_table(rows):
    """Turn a list of tuples (rows) into a black-bordered HTML table without headers."""
    if rows is None:
        return "<em>No remediation output.</em>"
    if isinstance(rows, str):
        return f"<pre>{rows}</pre>"
    if not rows:
        return "<em>No remediation output.</em>"

    tbody = ""
    for r in rows:
        if not isinstance(r, (list, tuple)):
            r = [r]
        tbody += "<tr>" + "".join(f"<td>{'' if c is None else c}</td>" for c in r) + "</tr>"
    return '<table class="black-table"><tbody>' + tbody + '</tbody></table>'


def normalize_severity(sev: str) -> str:
    """
    Normalize old labels -> new labels:
      Major -> High
      Minor -> Medium
    Keep Critical/High/Medium/Low as is.
    """
    if sev is None:
        return ""
    sev = str(sev).strip()
    if sev == "Major":
        return "High"
    if sev == "Minor":
        return "Medium"
    return sev


def severity_impact(sev: str) -> int:
    """
    Impact mapping:
      Critical = 4
      High     = 3
      Medium   = 2
      Low      = 1
    Unknown -> 0 (ignored)
    """
    sev = normalize_severity(sev)
    return {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1
    }.get(sev, 0)


def compute_risk_score(results):
    """
    ASCII model (no sigma):
      - Each test has a weight = impact (Critical=4, High=3, Medium=2, Low=1)
      - PASS => contributes 0 to failed_weight
      - FAIL => contributes its impact to failed_weight
      - ERROR => excluded from scoring
      - RiskScore = 100 * (failed_weight / total_weight)
    """
    failed_weight = 0
    total_weight = 0

    for r in results:
        st = r.get("Status", "")
        imp = severity_impact(r.get("Severity", ""))

        if st not in ("PASS", "FAIL"):
            continue
        if imp <= 0:
            continue

        total_weight += imp
        if st == "FAIL":
            failed_weight += imp

    if total_weight == 0:
        return None

    return round(100.0 * (failed_weight / total_weight), 2)


def risk_level_from_score(score):
    """
    Risk Score -> Level
      0–10   Low
      11–30  Medium
      31–60  High
      61–100 Critical
    """
    if score is None:
        return "N/A", ""
    if score <= 10:
        return "Low", "risk-low"
    if score <= 30:
        return "Medium", "risk-medium"
    if score <= 60:
        return "High", "risk-high"
    return "Critical", "risk-critical"


def execute_oracle_query(conn: oracledb.Connection, test):
    """
    SQL_Test must return exactly one row & one numeric column (e.g., SELECT COUNT(*) ...).
    Rule: value == 0 -> PASS, else -> FAIL.
    Message:
      - PASS  -> Text_Pass
      - FAIL  -> Text_Fail
      - ERROR -> empty
    Remediation (SQL_Detail): runs ONLY when FAIL.
    """
    result = {
        'Id': test['Id'],
        'Name': test['Name'],
        'Severity': normalize_severity(test.get('Severity') or ''),
        'Description': test.get('Description') or '',
        'Status': 'PENDING',
        'Message': '',
        'RemediationOutput': None,
    }

    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute(test['SQL_Test'])

        desc = cursor.description
        if not desc or len(desc) != 1:
            result['Status'] = 'ERROR'
            result['Message'] = ""
            return result

        row = cursor.fetchone()
        if row is None:
            result['Status'] = 'ERROR'
            result['Message'] = ""
            return result

        if cursor.fetchone() is not None:
            result['Status'] = 'ERROR'
            result['Message'] = ""
            return result

        val = row[0]
        if val is None:
            result['Status'] = 'ERROR'
            result['Message'] = ""
            return result

        try:
            count = int(val)
        except Exception:
            try:
                count = int(str(val).strip())
            except Exception:
                result['Status'] = 'ERROR'
                result['Message'] = ""
                return result

        if count == 0:
            result['Status'] = 'PASS'
            result['Message'] = test.get('Text_Pass') or ''
            result['RemediationOutput'] = None
        else:
            result['Status'] = 'FAIL'
            result['Message'] = test.get('Text_Fail') or ''
            sql_detail = (test.get('SQL_Detail') or '').strip()
            if sql_detail:
                try:
                    cursor.execute(sql_detail)
                    try:
                        rows = cursor.fetchall()
                    except Exception:
                        rows = []
                    result['RemediationOutput'] = rows
                except Exception as e:
                    result['RemediationOutput'] = f"Error running SQL_Detail: {e}"

    except Exception:
        result['Status'] = 'ERROR'
        result['Message'] = ""
    finally:
        if cursor:
            cursor.close()

    return result


def create_report_html(report_path, server_ip, port, service_name, connection_status, enabled_tests, results, oracle_user):
    """
    English report:
      - Target
      - Risk Score (with model text, no sigmas)
      - Under Risk Score: Summary table + Severity Matrix table (as you requested)
      - Test Results (PASS green, FAIL red, ERROR black)
    """

    # --- totals ---
    num_tests = len(enabled_tests) if enabled_tests is not None else 0
    num_failed = sum(1 for r in results if r['Status'] == 'FAIL')
    num_passed = sum(1 for r in results if r['Status'] == 'PASS')
    num_errors = sum(1 for r in results if r['Status'] == 'ERROR')

    # --- risk ---
    risk_score = compute_risk_score(results) if (connection_status == "SUCCESS") else None
    risk_level, risk_level_class = risk_level_from_score(risk_score)

    # --- severity matrix (use normalized severity) ---
    normalized_results = []
    for r in results:
        rr = dict(r)
        rr["Severity"] = normalize_severity(rr.get("Severity", ""))
        normalized_results.append(rr)

    severities = sorted({(r.get('Severity') or '') for r in normalized_results})
    sev_counts = {s: {'PASS': 0, 'FAIL': 0, 'ERROR': 0} for s in severities}
    for r in normalized_results:
        s = r.get('Severity') or ''
        st = r.get('Status')
        if s not in sev_counts:
            sev_counts[s] = {'PASS': 0, 'FAIL': 0, 'ERROR': 0}
        if st in sev_counts[s]:
            sev_counts[s][st] += 1

    # --- CSS ---
    styles = """
    <style>
      body { font-family: 'Inter', sans-serif; margin:0; background-color:#e9ecef; }
      .container-fluid { padding:30px; max-width:1200px; margin:auto; }
      .card-header { background-color:#0d6efd; color:#fff; }
      .black-table { width:100%; border-collapse:collapse; margin-bottom:16px; background:#fff; }
      .black-table th, .black-table td { border:2px solid #000; padding:8px; vertical-align:top; }
      .section-title { margin-top:24px; }

      /* Connection status */
      .status-success { color:green; font-weight:bold; }
      .status-fail { color:red; font-weight:bold; }

      /* Test status */
      .test-pass  { color:green; font-weight:bold; }
      .test-fail  { color:red; font-weight:bold; }
      .test-error { color:#000; font-weight:bold; }

      /* Risk */
      .risk-score { font-size:32px; font-weight:900; }
      .risk-low { color:#198754; font-size:26px; font-weight:900; }
      .risk-medium { color:#0dcaf0; font-size:26px; font-weight:900; }
      .risk-high { color:#fd7e14; font-size:26px; font-weight:900; }
      .risk-critical { color:#dc3545; font-size:26px; font-weight:900; }

      .small-muted { font-size: 12px; color:#333; }
    </style>
    """

    # --- Summary table ---
    summary_table = f"""
    <table class="black-table">
      <thead>
        <tr>
          <th>Total Tests</th>
          <th>Passed</th>
          <th>Failed</th>
          <th>Errors</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>{num_tests}</td>
          <td>{num_passed}</td>
          <td>{num_failed}</td>
          <td>{num_errors}</td>
        </tr>
      </tbody>
    </table>
    """

    # --- Severity Matrix table ---
    if severities:
        matrix_header = "<tr><th>Severity</th><th>Passed</th><th>Failed</th><th>Errors</th></tr>"
        matrix_rows = ""
        for s in severities:
            c = sev_counts[s]
            matrix_rows += f"<tr><td>{s}</td><td>{c['PASS']}</td><td>{c['FAIL']}</td><td>{c['ERROR']}</td></tr>"
        severity_matrix = f"""
        <table class="black-table">
          <thead>{matrix_header}</thead>
          <tbody>{matrix_rows}</tbody>
        </table>
        """
    else:
        severity_matrix = "<em>No results to build severity matrix.</em>"

    # --- Risk table (no sigma / no special chars) ---
    if connection_status == "SUCCESS" and risk_score is not None:
        risk_table = f"""
        <table class="black-table">
          <thead>
            <tr>
              <th style="width:260px;">Metric</th>
              <th>Value</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <th>Risk Score (0-100)</th>
              <td class="risk-score">{risk_score}</td>
            </tr>
            <tr>
              <th>Risk Level</th>
              <td class="{risk_level_class}">{risk_level}</td>
            </tr>
            <tr>
              <th>Model</th>
              <td>
                Normalized weighted failure score.
                <div class="small-muted" style="margin-top:6px;">
                  Impact weights: Critical=4, High=3, Medium=2, Low=1. Likelihood: PASS=0, FAIL=1.
                  RiskScore = 100 * (failed_weight / total_weight). ERROR tests are excluded from scoring.
                </div>
              </td>
            </tr>
          </tbody>
        </table>
        """
    elif connection_status == "SUCCESS":
        risk_table = "<em>Risk score could not be computed.</em>"
    else:
        risk_table = "<em>Risk score not computed because Oracle connection failed.</em>"

    # --- Test Results (colored) ---
    test_tables = ""
    if connection_status == 'SUCCESS':
        for r in normalized_results:
            remediation_html = format_table(r.get('RemediationOutput'))

            status_class = (
                "test-pass" if r.get("Status") == "PASS" else
                "test-fail" if r.get("Status") == "FAIL" else
                "test-error" if r.get("Status") == "ERROR" else
                ""
            )

            test_tables += f"""
            <table class="black-table">
              <thead><tr><th colspan="2">Test Result</th></tr></thead>
              <tbody>
                <tr><th style="width:220px;">Test Id</th><td>{r['Id']}</td></tr>
                <tr><th>Test Name</th><td>{r['Name']}</td></tr>
                <tr><th>Description</th><td>{r.get('Description','')}</td></tr>
                <tr><th>Severity</th><td>{r.get('Severity','')}</td></tr>
                <tr><th>Test Result</th><td class="{status_class}">{r.get('Status','')}</td></tr>
                <tr><th>Message</th><td>{r.get('Message','')}</td></tr>
                <tr><th>Remediation</th><td>{remediation_html}</td></tr>
              </tbody>
            </table>
            """
    else:
        test_tables = '<div class="text-danger">Tests were not executed: Oracle connection failed.</div>'

    # --- final HTML ---
    # IMPORTANT: Summary + Severity Matrix are placed UNDER Risk Score section (as requested)
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Oracle Security Assessment Report - {datetime.now().strftime("%Y-%m-%d")}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  {styles}
</head>
<body>
  <div class="container-fluid">
    <div class="card shadow-lg">
      <div class="card-header text-center">
        <h1 class="mb-0">Oracle Security Assessment Report</h1>
        <p class="mb-0">Generated at: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
      </div>
      <div class="card-body">
        <h2>1. Target Database & Connection</h2>
        <table class="black-table">
          <tbody>
            <tr><th style="width:220px;">Server Name / IP</th><td>{server_ip}</td></tr>
            <tr><th>Port</th><td>{port}</td></tr>
            <tr><th>Service Name</th><td>{service_name}</td></tr>
            <tr><th>User Name</th><td>{oracle_user}</td></tr>
            <tr>
              <th>Connection Status</th>
              <td class="{('status-success' if connection_status=='SUCCESS' else 'status-fail')}">{connection_status}</td>
            </tr>
          </tbody>
        </table>

        <h2 class="section-title">2. Risk Score</h2>
        {risk_table}

        <h2 class="section-title">3. Summary</h2>
        {summary_table}

        <h2 class="section-title">4. Severity Matrix</h2>
        {severity_matrix}

        <h2 class="section-title">5. Test Results</h2>
        {test_tables}
      </div>
      <div class="card-footer text-muted text-center">End of Report</div>
    </div>
  </div>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>"""

    try:
        os.makedirs(os.path.dirname(report_path) or ".", exist_ok=True)
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html)
        return True
    except Exception as e:
        print(f"[ERROR] Writing report file failed: {e}", file=sys.stderr)
        return False


def run_assessment_script(server_ip, port, service_name, report_path, oracle_user, oracle_password):
    """
    Load tests from MySQL, connect to Oracle, run each test with execute_oracle_query,
    and write the HTML report. No mocking.
    """
    enabled_tests = get_enabled_tests()

    dsn = f"{server_ip}:{port}/{service_name}"
    connection_status = "PENDING"
    oracle_conn = None
    results = []

    try:
        print(f"[INFO] Connecting to Oracle DSN={dsn} user={oracle_user}")
        oracle_conn = oracledb.connect(user=oracle_user, password=oracle_password, dsn=dsn)
        connection_status = "SUCCESS"
        print("[INFO] Oracle connection SUCCESS")

        for test in enabled_tests:
            r = execute_oracle_query(oracle_conn, test)
            results.append(r)

    except Exception as e:
        connection_status = f"FAILED: {e}"
        print(f"[ERROR] Oracle connection or execution failed: {e}", file=sys.stderr)

    finally:
        ok = create_report_html(
            report_path=report_path,
            server_ip=server_ip,
            port=port,
            service_name=service_name,
            connection_status=connection_status,
            enabled_tests=enabled_tests,
            results=results,
            oracle_user=oracle_user
        )

        if oracle_conn:
            try:
                oracle_conn.close()
            except Exception:
                pass

        if not ok:
            sys.exit(1)

        if connection_status != "SUCCESS":
            sys.exit(1)

        print(f"[INFO] Report generated at: {report_path}")
        sys.exit(0)


if __name__ == "__main__":
    # Five command-line args. Password is provided over stdin instead of argv.
    if len(sys.argv) != 6:
        print("Usage: python run_assessment.py <server_ip> <port> <service_name> <report_path> <oracle_user>", file=sys.stderr)
        sys.exit(1)

    server_ip = sys.argv[1]
    port = sys.argv[2]
    service_name = sys.argv[3]
    report_path = sys.argv[4]
    oracle_user = sys.argv[5]
    oracle_password = sys.stdin.read()

    run_assessment_script(server_ip, port, service_name, report_path, oracle_user, oracle_password)
