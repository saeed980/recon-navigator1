# modules/web_handlers.py

WEB_MATRIX = {
    "cms_wordpress": {
        "keywords": ["wordpress", "wp-content", "wp-includes", "xmlrpc.php"],
        "title": "🧬 Tech Stack: WordPress CMS Context",
        "severity": "Medium (حسب الإضافات المنصبة)",
        "methodology": "• نواة الووردبريس غالباً آمنة، لكن الإضافات (Plugins) والقوالب هي منجم الثغرات.\n• اختبر مسارات الإضافات بحثاً عن ثغرات XSS و SQLi غير المكتشفة (0-days).\n• افحص ملف الـ xmlrpc.php لمعرفة إذا كان يتيح تخمين كلمات المرور (Brute Force).",
        "command": "wpscan --url [TARGET] --enumerate p,t,u --plugins-detection aggressive"
    },
    "web_frameworks": {
        "keywords": ["react", "angular", "vue.js", "next.js", "webpack", "nuxt", "jquery"],
        "title": "⚛️ Client-Side Stack: Modern JS Framework (SPA)",
        "severity": "Informational (تحتوي على تسريبات سرية)",
        "methodology": "• التطبيقات الحديثة تقوم بتنزيل المنطق البرمجي بالكامل على متصفح الضحية.\n• قم بتحليل ملفات الـ JS وسحب الـ Source Maps إن وجدت.\n• استخرج الـ Endpoints المخفية ومفاتيح الـ API الممررة بالخطأ بالداخل.",
        "command": "secretfinder -i [JS_URL] -o cli"
    },
    "waf_defense": {
        "keywords": ["cloudflare", "akamai", "sucuri", "incapsula", "f5 big-ip", "waf"],
        "title": "🛡️ Security Layer: Web Application Firewall (WAF) Detected",
        "severity": "Informational (حظر تكتيكي تكسيري)",
        "methodology": "• الهدف محمي بالكامل، الفحص العشوائي المكثف سيؤدي لحظر الـ IP الخاص بك فوراً.\n• استراتيجيتك هي العثور على الـ Origin IP (الـ IP الحقيقي للخادم) لتخطي الـ WAF والضرب مباشرة.\n• ابحث في سجلات التاريخ لـ DNS أو شهادات SSL القديمة في Censys/Shodan.",
        "command": "wafw00f [TARGET] && shodan domain [DOMAIN]"
    }
}
