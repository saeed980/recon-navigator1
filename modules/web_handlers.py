# modules/web_handlers.py

WEB_MATRIX = {
    "url_parameters": {
        "keywords": ["?", "=", "&", "searchquery", "page=", "sortby=", "id=", "url="],
        "title": "🎯 Web Attack Surface: Active URL Parameters Detected",
        "severity": "Medium to High (قابل للحقن والتلاعب)",
        "methodology": "• الرابط يحتوي على بارامترات نشطة ممررة للخلفية (مثل searchQuery أو sortby).\n• اختبر فوراً ثغرات Reflected XSS عبر حقن وسوم مثل `\"><script>alert(1)</script>` في قيم البارامترات.\n• إذا كان البارامتر يحتوي على أرقام معرفية (مثل الكورسات أو المستخدمين)، اختبر ثغرات IDOR/BOLA عبر تغيير الأرقام.\n• مرر الرابط لأداة SQLMap لفحص إمكانية حقن قواعد البيانات من خلال البارامترات المفتوحة.",
        "command": "echo '[URL]' | qsreplace '\"><script>alert(1)</script>' | kxss"
    },
    
    "static_html_routes": {
        "keywords": [".html", ".htm", ".php", ".aspx", ".jsp"],
        "title": "🌐 Tech Stack: Server-Side Routing & File Extensions",
        "severity": "Informational",
        "methodology": "• الموقع يظهر امتدادات ملفات صريحة (مثل .html أو .php)، مما يسهل معرفة البيئة الخلفية والسيرفر المشغل.\n• ابحث عن ثغرات الملفات المتروكة أو النسخ الاحتياطية (مثل .php.bak) أو صفحات الخطأ التي تسرب مسارات السيرفر الكاملة (Full Path Disclosure).",
        "command": "dirsearch -u [TARGET] -e html,php,txt,bak,json -x 404"
    },

    "cms_wordpress": {
        "keywords": ["wordpress", "wp-content", "wp-includes", "xmlrpc.php"],
        "title": "🧬 Tech Stack: WordPress CMS Context",
        "severity": "Medium (حسب الإضافات المنصبة)",
        "methodology": "• نواة الووردبريس غالباً آمنة، لكن الإضافات (Plugins) والقوالب هي منجم الثغرات العالمي.\n• اختبر مسارات الإضافات بحثاً عن ثغرات XSS و SQLi غير المكتشفة أو المعروفة بـ CVEs.\n• افحص ملف الـ xmlrpc.php لمعرفة إذا كان يتيح تخمين كلمات المرور (Brute Force) أو الـ Pingback Attack.",
        "command": "wpscan --url [TARGET] --enumerate p,t,u --plugins-detection aggressive"
    },
    
    "web_frameworks": {
        "keywords": ["react", "angular", "vue.js", "next.js", "webpack", "nuxt", "jquery"],
        "title": "⚛️ Client-Side Stack: Modern JS Framework (SPA)",
        "severity": "Informational (تحتوي على تسريبات سرية داخل الأكواد)",
        "methodology": "• التطبيقات الحديثة تقوم بتنزيل المنطق البرمجي بالكامل على متصفح الضحية.\n• قم بتحليل ملفات الـ JS وسحب الـ Source Maps إن وجدت.\n• استخرج الـ Endpoints المخفية ومفاتيح الـ API الممررة بالخطأ من المطورين بالداخل.",
        "command": "secretfinder -i [JS_URL] -o cli"
    },
    
    "waf_defense": {
        "keywords": ["cloudflare", "akamai", "sucuri", "incapsula", "f5 big-ip", "waf"],
        "title": "🛡️ Security Layer: Web Application Firewall (WAF) Detected",
        "severity": "Informational (حظر تكتيكي تكسيري)",
        "methodology": "• الهدف محمي بالكامل، الفحص العشوائي المكثف سيؤدي لحظر الـ IP الخاص بك فوراً.\n• استراتيجيتك هي العثور على الـ Origin IP (الـ IP الحقيقي للخادم) لتخطي الـ WAF والضرب خلف جدار الحماية مباشرة.\n• ابحث في سجلات التاريخ لـ DNS أو شهادات SSL القديمة في Censys أو Shodan.",
        "command": "wafw00f [TARGET] && shodan domain [DOMAIN]"
    }
}
