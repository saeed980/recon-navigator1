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
"url_parameters": {
        "keywords": ["?", "=", "&", "searchquery", "page=", "sortby="],
        "title": "🎯 Web Attack Surface: Active URL Parameters Detected",
        "severity": "Medium to High",
        "methodology": "• الرابط يحتوي على بارامترات نشطة ممررة للخلفية (مثل searchQuery أو sortby).\n• اختبر فوراً ثغرات Reflected XSS عبر حقن وسوم مثل `<script>` في قيم البارامترات.\n• مرر الرابط لأداة SQLMap لفحص إمكانية حقن قواعد البيانات من خلال البارامترات المفتوحة.",
        "command": "gau [TARGET] | grep '=' | qsreplace '\"><script>alert(1)</script>' | kxss"
    },
    "static_html_routes": {
        "keywords": [".html", ".htm", ".php", ".aspx"],
        "title": "🌐 Tech Stack: Server-Side Routing & File Extensions",
        "severity": "Informational",
        "methodology": "• الموقع يظهر امتدادات ملفات صريحة (مثل .html أو .php)، مما يسهل معرفة البيئة الخلفية.\n• ابحث عن ثغرات الملفات المتروكة أو صفحات الخطأ التي تسرب مسارات السيرفر الكاملة (Full Path Disclosure).",
        "command": "dirsearch -u [TARGET] -e html,php,txt,bak"
    }
