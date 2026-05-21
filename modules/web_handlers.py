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
