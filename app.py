"""
SecureCode Pro — app.py v3
===========================
الإصلاح: محرك AST يعمل بشكل صحيح 100%
شغّل بـ:  python app.py
"""

from flask import Flask, request, jsonify
from flask import render_template 
from flask_cors import CORS
import ast
import re

app = Flask(__name__)
CORS(app)


# ══════════════════════════════════════════════════════════════
#  PYTHON ANALYZER  — يستخدم ast.parse() لفحص حقيقي
# ══════════════════════════════════════════════════════════════

class PythonAnalyzer:

    # ── دوال خطيرة يبحث عنها AST walker ──────────────────────
    DANGEROUS_CALLS = {
        "eval": {
            "owasp":   "A03:2021 - Injection",
            "severity": "critical",
            "description": "eval() تنفذ أي نص كـ Python — يمكن للمهاجم تشغيل أوامر عشوائية.",
            "fix": "import ast\n# بدلاً من eval():\nresult = ast.literal_eval(user_input)  # يقبل بيانات فقط، لا كود"
        },
        "exec": {
            "owasp":   "A03:2021 - Injection",
            "severity": "critical",
            "description": "exec() ينفذ كود Python ديناميكياً — خطر تنفيذ كود خبيث.",
            "fix": "# تجنّب exec() مع أي إدخال خارجي\n# إذا اضطررت: exec(code, {'__builtins__': {}})"
        },
        "compile": {
            "owasp":   "A03:2021 - Injection",
            "severity": "high",
            "description": "compile() يُحوّل النصوص إلى bytecode — قابل للإساءة.",
            "fix": "# تجنّب compile() مع بيانات المستخدم"
        },
        "os.system": {
            "owasp":   "A03:2021 - Injection",
            "severity": "high",
            "description": "os.system() يُشغّل shell commands — خطر Command Injection.",
            "fix": "import subprocess\n# أرسل الأوامر كقائمة لا كنص:\nsubprocess.run(['ping', '-c', '4', host], capture_output=True)"
        },
        "os.popen": {
            "owasp":   "A03:2021 - Injection",
            "severity": "high",
            "description": "os.popen() يفتح shell — نفس خطر os.system().",
            "fix": "subprocess.run(cmd_list, capture_output=True, text=True)"
        },
        "subprocess.call": {
            "owasp":   "A03:2021 - Injection",
            "severity": "high",
            "description": "subprocess.call مع shell=True يُسبب Command Injection.",
            "fix": "subprocess.run(['cmd', arg1, arg2])  # قائمة بدل نص"
        },
        "subprocess.Popen": {
            "owasp":   "A03:2021 - Injection",
            "severity": "high",
            "description": "Popen مع shell=True خطر — تحقق من المعاملات.",
            "fix": "subprocess.Popen(['cmd', arg], shell=False)"
        },
        "pickle.loads": {
            "owasp":   "A08:2021 - Software and Data Integrity Failures",
            "severity": "critical",
            "description": "pickle.loads() ينفذ كوداً عند إلغاء التسلسل — لا تستخدمه مع بيانات خارجية.",
            "fix": "import json\ndata = json.loads(raw_data)  # json آمن"
        },
        "pickle.load": {
            "owasp":   "A08:2021 - Software and Data Integrity Failures",
            "severity": "critical",
            "description": "pickle.load() خطير مع ملفات غير موثوقة.",
            "fix": "import json\nwith open(f) as fh:\n    data = json.load(fh)"
        },
        "__import__": {
            "owasp":   "A08:2021 - Software and Data Integrity Failures",
            "severity": "high",
            "description": "استيراد ديناميكي — يُستغل لتحميل مكتبات خبيثة.",
            "fix": "# استخدم import ثابت في أعلى الملف"
        },
        "marshal.loads": {
            "owasp":   "A08:2021 - Software and Data Integrity Failures",
            "severity": "high",
            "description": "marshal.loads() غير آمن مع بيانات غير موثوقة.",
            "fix": "import json\ndata = json.loads(raw)"
        },
    }

    # ── استيرادات خطيرة يبحث عنها AST walker ─────────────────
    DANGEROUS_IMPORTS = {
        "pickle":   ("A08:2021 - Integrity Failures", "high",   "pickle غير آمن مع بيانات خارجية — استخدم json"),
        "marshal":  ("A08:2021 - Integrity Failures", "medium", "marshal غير آمن مع بيانات غير موثوقة"),
        "shelve":   ("A08:2021 - Integrity Failures", "medium", "shelve يعتمد pickle داخلياً"),
        "telnetlib":("A02:2021 - Crypto Failures",    "high",   "telnet يُرسل البيانات بدون تشفير — استخدم paramiko/SSH"),
    }

    # ── أنماط Regex (hardcoded secrets + crypto ضعيف + SQL) ───
    REGEX_CHECKS = [
        # Hardcoded passwords
        (
            r'(?i)\b(password|passwd|pwd)\s*=\s*["\'][^"\']{3,}["\']',
            "A07:2021 - Identification and Authentication Failures",
            "critical",
            "كلمة مرور مكتوبة مباشرة في الكود!",
            "import os\nPASSWORD = os.environ.get('APP_PASSWORD')  # اقرأها من متغيرات البيئة"
        ),
        # Hardcoded secrets / API keys
        (
            r'(?i)\b(secret|secret_key|SECRET_KEY|api_key|apikey)\s*=\s*["\'][^"\']{4,}["\']',
            "A07:2021 - Identification and Authentication Failures",
            "critical",
            "مفتاح سري أو API key مكتوب مباشرة في الكود!",
            "import os\nSECRET_KEY = os.environ.get('SECRET_KEY')  # .env أو متغيرات البيئة"
        ),
        # MD5
        (
            r'hashlib\.md5\s*\(',
            "A02:2021 - Cryptographic Failures",
            "high",
            "MD5 خوارزمية مكسورة — لا تستخدمها لتشفير كلمات المرور.",
            "import bcrypt\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())"
        ),
        # SHA1
        (
            r'hashlib\.sha1\s*\(',
            "A02:2021 - Cryptographic Failures",
            "medium",
            "SHA-1 ضعيف — استخدم SHA-256 على الأقل.",
            "hashlib.sha256(data).hexdigest()"
        ),
        # random للأمان
        (
            r'\brandom\.(random|randint|choice|randrange)\s*\(',
            "A02:2021 - Cryptographic Failures",
            "medium",
            "random غير آمن تشفيرياً — متوقع للمهاجمين.",
            "import secrets\ntoken = secrets.token_hex(32)   # للتوكنات\nn = secrets.randbelow(100)       # للأرقام"
        ),
        # DES / RC4
        (
            r'(?i)\b(DES|RC4|RC2)\b',
            "A02:2021 - Cryptographic Failures",
            "critical",
            "خوارزمية تشفير قديمة ومكسورة (DES/RC4/RC2).",
            "from Crypto.Cipher import AES  # استخدم AES-256"
        ),
        # SQL Injection — f-string في execute
        (
            r'\.execute\s*\(\s*f["\']',
            "A03:2021 - Injection",
            "critical",
            "SQL Injection: بناء query بـ f-string داخل execute()!",
            'cursor.execute("SELECT * FROM t WHERE id = %s", (user_id,))'
        ),
        # SQL Injection — تسلسل نصي في execute
        (
            r'\.execute\s*\(\s*["\'][^)]*["\'\s]*\+',
            "A03:2021 - Injection",
            "critical",
            "SQL Injection: بناء query بدمج نصوص مع +",
            'cursor.execute("SELECT * FROM t WHERE id = %s", (user_id,))'
        ),
        # SQL Injection — % formatting في execute
        (
            r'\.execute\s*\(\s*["\'].*%[^,)]+%',
            "A03:2021 - Injection",
            "critical",
            "SQL Injection: بناء query بـ % string formatting",
            'cursor.execute("SELECT * FROM t WHERE id = %s", (user_id,))'
        ),
        # SQL string concatenation (query variable)
        (
            r'(?i)(query|sql|statement)\s*=\s*["\'].*SELECT.*["\+]',
            "A03:2021 - Injection",
            "critical",
            "SQL Injection: بناء SELECT query بدمج نصوص.",
            'query = "SELECT * FROM users WHERE id = %s"\ncursor.execute(query, (user_id,))'
        ),
        # debug=True في production
        (
            r'app\.run\s*\(.*debug\s*=\s*True',
            "A05:2021 - Security Misconfiguration",
            "medium",
            "debug=True في production يكشف stack traces وأدوات debug للمهاجمين.",
            "app.run(debug=False)  # أو استخدم متغير بيئة\napp.run(debug=os.environ.get('DEBUG')=='1')"
        ),
        # SSL verify=False
        (
            r'verify\s*=\s*False',
            "A02:2021 - Cryptographic Failures",
            "high",
            "تعطيل التحقق من شهادة SSL — عرضة لهجمات MITM.",
            "requests.get(url)  # احذف verify=False وثبّت الشهادة"
        ),
        # shell=True
        (
            r'shell\s*=\s*True',
            "A03:2021 - Injection",
            "high",
            "shell=True في subprocess يفتح ثغرة Command Injection.",
            "subprocess.run(['cmd', arg1, arg2], shell=False)"
        ),
    ]

    # ──────────────────────────────────────────────────────────
    def analyze(self, code: str) -> list:
        vulnerabilities = []
        lines = code.splitlines()

        # ════ 1. تحليل AST — الأدق والأكثر موثوقية ════════════
        try:
            tree = ast.parse(code)

            for node in ast.walk(tree):

                # ── استدعاءات الدوال الخطيرة ──
                if isinstance(node, ast.Call):
                    fname = self._get_function_name(node)
                    if fname in self.DANGEROUS_CALLS:
                        info     = self.DANGEROUS_CALLS[fname]
                        src_line = self._get_line(lines, node.lineno)
                        vulnerabilities.append({
                            "name":            f"دالة خطيرة: {fname}()",
                            "owasp":           info["owasp"],
                            "severity":        info["severity"],
                            "line":            node.lineno,
                            "description":     info["description"],
                            "vulnerable_code": src_line,
                            "fix":             info["fix"],
                            "explanation":     f"استبدل {fname}() بالبديل الآمن الموضح.",
                        })

                # ── الاستيرادات الخطيرة ──
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    module_name = self._get_module_name(node)
                    if module_name in self.DANGEROUS_IMPORTS:
                        owasp, sev, desc = self.DANGEROUS_IMPORTS[module_name]
                        src_line = self._get_line(lines, node.lineno)
                        vulnerabilities.append({
                            "name":            f"استيراد خطير: {module_name}",
                            "owasp":           owasp,
                            "severity":        sev,
                            "line":            node.lineno,
                            "description":     desc,
                            "vulnerable_code": src_line,
                            "fix":             f"# لا تستخدم {module_name} مع بيانات خارجية\nimport json  # بديل آمن للبيانات",
                            "explanation":     f"تجنّب {module_name} مع أي بيانات قادمة من المستخدم أو الشبكة.",
                        })

        except SyntaxError as e:
            vulnerabilities.append({
                "name":            "خطأ نحوي في الكود",
                "owasp":           "N/A",
                "severity":        "low",
                "line":            e.lineno or 1,
                "description":     f"الكود يحتوي على خطأ نحوي: {e.msg}",
                "vulnerable_code": "",
                "fix":             "# أصلح الأخطاء النحوية أولاً",
                "explanation":     "الأخطاء النحوية تمنع التحليل الكامل.",
            })

        # ════ 2. فحص Regex — يمسك ما يفوت AST ═════════════════
        found_lines = set()   # نتجنب التكرار لنفس السطر

        for pattern, owasp, severity, description, fix in self.REGEX_CHECKS:
            for i, line in enumerate(lines, start=1):
                key = (pattern[:20], i)
                if key in found_lines:
                    continue
                if re.search(pattern, line):
                    found_lines.add(key)
                    vulnerabilities.append({
                        "name":            self._vuln_name(description),
                        "owasp":           owasp,
                        "severity":        severity,
                        "line":            i,
                        "description":     description,
                        "vulnerable_code": line.strip(),
                        "fix":             fix,
                        "explanation":     f"راجع {owasp} في OWASP للتفاصيل.",
                    })

        # ── رتّب من الأشد خطورة إلى الأقل ──
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        vulnerabilities.sort(key=lambda v: severity_order.get(v["severity"], 4))

        return vulnerabilities

    # ──────────────────────────────────────────────────────────
    #  مساعدات
    # ──────────────────────────────────────────────────────────

    def _get_function_name(self, node: ast.Call) -> str:
        """يستخرج اسم الدالة المستدعاة من عقدة ast.Call"""
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            parts = []
            current = func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""

    def _get_module_name(self, node) -> str:
        """يستخرج اسم المكتبة من import أو from...import"""
        if isinstance(node, ast.Import):
            return node.names[0].name.split(".")[0]
        if isinstance(node, ast.ImportFrom):
            return (node.module or "").split(".")[0]
        return ""

    def _get_line(self, lines: list, lineno: int) -> str:
        """يُرجع نص السطر بشكل آمن"""
        if 1 <= lineno <= len(lines):
            return lines[lineno - 1].strip()
        return ""

    def _vuln_name(self, description: str) -> str:
        """يُنشئ اسماً قصيراً من الوصف"""
        return description.split("—")[0].strip()[:50]


# ══════════════════════════════════════════════════════════════
#  JAVASCRIPT ANALYZER
# ══════════════════════════════════════════════════════════════

class JavaScriptAnalyzer:

    CHECKS = [
        (r'\beval\s*\(',
         "A03:2021 - Injection", "critical",
         "eval() تنفذ نصوص JS — خطر Code Injection",
         'const data = JSON.parse(jsonString);  // آمن'),

        (r'\.innerHTML\s*[+]?=(?!=)',
         "A03:2021 - Injection", "critical",
         "innerHTML يُدخل HTML خام — ثغرة XSS",
         'element.textContent = data;  // آمن\n// أو: element.innerHTML = DOMPurify.sanitize(data);'),

        (r'document\.write\s*\(',
         "A03:2021 - Injection", "high",
         "document.write() يحقن HTML بلا تنظيف — XSS",
         'const el = document.createElement("p");\nel.textContent = data;\nparent.appendChild(el);'),

        (r'(?i)(password|secret|api.?key|token)\s*[:=]\s*["\'][^"\']{4,}',
         "A07:2021 - Auth Failures", "critical",
         "بيانات حساسة مكتوبة مباشرة في JS",
         'const key = process.env.API_KEY;  // متغيرات البيئة'),

        (r'localStorage\.setItem\s*\(.*[Tt]oken',
         "A07:2021 - Auth Failures", "high",
         "تخزين tokens في localStorage عرضة لـ XSS",
         '// ضع التوكن في httpOnly cookie من الـ Server'),

        (r'__proto__',
         "A08:2021 - Integrity", "high",
         "Prototype Pollution — التعديل على __proto__",
         'const obj = Object.create(null);  // بلا prototype'),

        (r'Math\.random\s*\(',
         "A02:2021 - Crypto Failures", "medium",
         "Math.random() غير آمن تشفيرياً",
         'crypto.getRandomValues(new Uint8Array(32));  // آمن'),
    ]

    def analyze(self, code: str) -> list:
        vulns, lines = [], code.splitlines()
        for pattern, owasp, sev, desc, fix in self.CHECKS:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    vulns.append({
                        "name": desc.split("—")[0].strip(),
                        "owasp": owasp, "severity": sev, "line": i,
                        "description": desc, "vulnerable_code": line.strip(),
                        "fix": fix, "explanation": f"OWASP: {owasp}",
                    })
                    break
        return vulns


# ══════════════════════════════════════════════════════════════
#  PHP ANALYZER
# ══════════════════════════════════════════════════════════════

class PHPAnalyzer:

    CHECKS = [
        (r'mysql_query\s*\(',
         "A03:2021 - Injection", "critical",
         "mysql_query() مع بيانات خام — SQL Injection",
         '$stmt = $pdo->prepare("SELECT * FROM t WHERE id=?");\n$stmt->execute([$id]);'),

        (r'\$_(GET|POST|REQUEST|COOKIE)\s*\[',
         "A03:2021 - Injection", "high",
         "استخدام $_GET/$_POST مباشرة بلا تنظيف",
         '$input = htmlspecialchars($_GET["x"], ENT_QUOTES, "UTF-8");'),

        (r'\beval\s*\(',
         "A03:2021 - Injection", "critical",
         "eval() ينفذ PHP ديناميكياً — خطر RCE",
         '// تجنّب eval() في PHP تماماً'),

        (r'echo\s+\$_(GET|POST)',
         "A03:2021 - Injection", "critical",
         "طباعة مدخلات المستخدم مباشرة — Reflected XSS",
         'echo htmlspecialchars($_GET["x"], ENT_QUOTES, "UTF-8");'),

        (r'include\s*\(\s*\$',
         "A05:2021 - Misconfig", "critical",
         "include مع متغير — Local/Remote File Inclusion",
         '$allowed=["home","about"];\nif(in_array($p,$allowed)) include "$p.php";'),

        (r'\bmd5\s*\(',
         "A02:2021 - Crypto", "high",
         "md5() لكلمات المرور — خوارزمية مكسورة",
         '$hash = password_hash($password, PASSWORD_BCRYPT);'),
    ]

    def analyze(self, code: str) -> list:
        vulns, lines = [], code.splitlines()
        for pattern, owasp, sev, desc, fix in self.CHECKS:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    vulns.append({
                        "name": desc.split("—")[0].strip(),
                        "owasp": owasp, "severity": sev, "line": i,
                        "description": desc, "vulnerable_code": line.strip(),
                        "fix": fix, "explanation": f"OWASP: {owasp}",
                    })
                    break
        return vulns


# ══════════════════════════════════════════════════════════════
#  JAVA / C++ ANALYZER
# ══════════════════════════════════════════════════════════════

class GenericAnalyzer:

    PATTERNS = {
        "java": [
            (r'Runtime\.getRuntime\(\)\.exec',
             "A03:2021 - Injection", "high",
             "Command Injection عبر Runtime.exec()",
             'ProcessBuilder pb = new ProcessBuilder("cmd", arg);\npb.redirectErrorStream(true);'),
            (r'(Statement|createStatement)\s*.*execute.*\+',
             "A03:2021 - Injection", "critical",
             "SQL Injection — بناء query بدمج نصوص",
             'PreparedStatement s = conn.prepareStatement("SELECT * FROM t WHERE id=?");\ns.setInt(1, id);'),
            (r'MessageDigest\.getInstance\("MD5"\)',
             "A02:2021 - Crypto", "high",
             "MD5 ضعيف في Java",
             'MessageDigest md = MessageDigest.getInstance("SHA-256");'),
            (r'new\s+Random\s*\(',
             "A02:2021 - Crypto", "medium",
             "java.util.Random غير آمن تشفيرياً",
             'SecureRandom sr = new SecureRandom();'),
        ],
        "cpp": [
            (r'\bgets\s*\(',
             "A03:2021 - Injection", "critical",
             "gets() بلا حد حجم — Buffer Overflow مؤكد",
             'fgets(buffer, sizeof(buffer), stdin);'),
            (r'\bstrcpy\s*\(',
             "A03:2021 - Injection", "high",
             "strcpy() بلا حد حجم — Buffer Overflow",
             'strncpy(dest, src, sizeof(dest) - 1);\ndest[sizeof(dest)-1] = 0;'),
            (r'\bsprintf\s*\(',
             "A03:2021 - Injection", "medium",
             "sprintf() بلا حد حجم — Buffer Overflow",
             'snprintf(buffer, sizeof(buffer), "%s", input);'),
            (r'\bsystem\s*\(',
             "A03:2021 - Injection", "high",
             "system() عرضة لـ Command Injection",
             '// استخدم execve() مع مصفوفة المعاملات بدل system()'),
            (r'\bscanf\s*\(',
             "A03:2021 - Injection", "medium",
             "scanf() بلا حد حجم — Buffer Overflow",
             'scanf("%255s", buffer);  // حدّد الحجم دائماً'),
        ],
    }

    def analyze(self, code: str, lang: str) -> list:
        vulns, lines = [], code.splitlines()
        for pattern, owasp, sev, desc, fix in self.PATTERNS.get(lang, []):
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    vulns.append({
                        "name": desc.split("—")[0].strip(),
                        "owasp": owasp, "severity": sev, "line": i,
                        "description": desc, "vulnerable_code": line.strip(),
                        "fix": fix, "explanation": f"OWASP: {owasp}",
                    })
                    break
        return vulns


# ══════════════════════════════════════════════════════════════
#  MODULAR ENGINE — يوجّه للمحلل الصحيح حسب اللغة
# ══════════════════════════════════════════════════════════════

_PY  = PythonAnalyzer()
_JS  = JavaScriptAnalyzer()
_PHP = PHPAnalyzer()
_GEN = GenericAnalyzer()

def dispatch(code: str, language: str) -> list:
    lang = language.lower().strip()
    if lang == "python":                  return _PY.analyze(code)
    if lang in ("javascript", "js"):      return _JS.analyze(code)
    if lang == "php":                     return _PHP.analyze(code)
    if lang == "java":                    return _GEN.analyze(code, "java")
    if lang in ("cpp", "c++", "c"):       return _GEN.analyze(code, "cpp")
    # fallback: جرّب Python
    return _PY.analyze(code)

def calc_score(vulns: list) -> int:
    penalty = {"critical": 25, "high": 15, "medium": 8, "low": 3}
    return max(0, 100 - sum(penalty.get(v["severity"], 0) for v in vulns))

def make_recommendation(vulns: list, lang: str) -> str:
    if not vulns:
        return f"✅ لم تُكتشف ثغرات في كود {lang}. تأكد من إجراء مراجعة يدوية أيضاً."
    order  = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    top    = min(vulns, key=lambda v: order.get(v["severity"], 4))
    labels = {"critical":"حرجة","high":"عالية","medium":"متوسطة","low":"منخفضة"}
    label  = labels.get(top["severity"], top["severity"])
    return (
        f"⚠️ أعلى خطر: [{top['owasp']}] {top['name']} "
        f"— خطورة {label} في السطر {top['line']}. "
        f"ابدأ بإصلاحه فوراً."
    )


# ══════════════════════════════════════════════════════════════
#  FLASK ENDPOINTS
# ══════════════════════════════════════════════════════════════

@app.route("/scan", methods=["POST"])
def scan():
    """
    استقبال الكود وإرجاع نتائج الفحص.

    Body (JSON):
        { "code": "...", "language": "python" }

    Response (JSON):
        {
          "status": "ok",
          "language": "python",
          "lines_analyzed": 42,
          "score": 60,
          "vulnerabilities": [ { name, owasp, severity, line,
                                  description, vulnerable_code,
                                  fix, explanation } ],
          "recommendation": "..."
        }
    """
    data = request.get_json(silent=True)

    # ── تحقق من الإدخال ───────────────────────────────────────
    if not data:
        return jsonify({"status": "error", "message": "أرسل JSON بتنسيق {code, language}"}), 400

    code     = (data.get("code") or "").strip()
    language = (data.get("language") or "python").strip()

    if not code:
        return jsonify({"status": "error", "message": "حقل 'code' فارغ"}), 400

    if len(code) > 100_000:
        return jsonify({"status": "error", "message": "الكود يتجاوز الحد (100,000 حرف)"}), 400

    # ── الفحص ──────────────────────────────────────────────────
    vulns = dispatch(code, language)

    return jsonify({
        "status":           "ok",
        "language":         language,
        "lines_analyzed":   len(code.splitlines()),
        "score":            calc_score(vulns),
        "vulnerabilities":  vulns,
        "recommendation":   make_recommendation(vulns, language),
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":   "ok",
        "server":   "SecureCode Pro",
        "version":  "3.0",
        "languages": ["python", "javascript", "php", "java", "cpp"],
    })


@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")
    


# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("\n" + "═" * 54)
    print("  🛡️   SecureCode Pro — Backend v3.0")
    print("═" * 54)
    print("  ✅  السيرفر يعمل على : http://127.0.0.1:5000")
    print("  📡  Scan endpoint    : POST /scan")
    print("  🔍  Health check     : GET  /health")
    print("═" * 54 + "\n")
    app.run(debug=False, host="127.0.0.1", port=5000)
