# modules/web_handlers.py

WEB_MATRIX = {
    "vun_xss": {
        "keywords": ["xss", "cross-site scripting", "<script>", "alert(", "onload=", "searchquery", "q="],
        "title": "🎯 Vulnerability Context: Cross-Site Scripting (XSS)",
        "severity": "Medium to High",
        "methodology": "• ابحث عن البارامترات المنعكسة في الصفحة (Reflected) أو المخزنة في قاعدة البيانات (Stored).\n• اختبر تخطي الفلاتر (WAF Bypass) باستخدام وسم الاستدعاء الخاطئ مثل `<svg onload=alert(1)>` أو عبر الـ Markdown Polyglots.\n• افحص سياق الحقن: هل أنت داخل وسم نصي، داخل خاصية (Attribute)، أم داخل كود JavaScript صريح؟",
        "command": "echo '[TARGET]' | gau | grep '=' | qsreplace '\"><svg onload=confirm(1)>' | kxss"
    },
    "vun_csrf": {
        "keywords": ["csrf", "xsrf", "cross-site request forgery", "anti-csrf", "csrf-token"],
        "title": "🛡️ Vulnerability Context: Cross-Site Request Forgery (CSRF)",
        "severity": "Medium to High",
        "methodology": "• ابحث عن الطلبات الحساسة (تغيير كلمة المرور، تعديل البريد، حذف الحساب) التي تعتمد فقط على الـ Session Cookies.\n• اختبر إزالة توكن الـ CSRF بالكامل أو إرساله فارغاً لمعرفة هل يتحقق السيرفر من وجوده أم قيمته فقط.\n• جرب تبديل نوع الطلب من POST إلى GET لمعرفة إذا كان السيرفر يقبل التمرير العشوائي.",
        "command": "🎯 تكتيك يدوي: قم بتوليد CSRF PoC Form عبر Burp Suite واختبر تنفيذه في متصفح معزول."
    },
    "vun_host_header": {
        "keywords": ["host header", "x-forwarded-host", "host injection", "password reset poison"],
        "title": "🌐 Vulnerability Context: Host Header Injection",
        "severity": "Low to High",
        "methodology": "• قم بالتلاعب بقيمة ترويسة `Host:` في الطلب وراقب هل يقوم السيرفر بتحويلك أو تضمين الرابط في روابط الصفحة.\n• اختبر إضافة ترويسات رديفة مثل `X-Forwarded-Host: evil.com` أو `Forwarded: host=evil.com`.\n• افحص ميزة استعادة كلمة المرور: هل يتم توليد رابط الاستعادة بناءً على الـ Host المزور؟ (Password Reset Poisoning).",
        "command": "curl -H \"Host: evil.com\" -H \"X-Forwarded-Host: evil.com\" [TARGET]"
    },
    "vun_open_redirect": {
        "keywords": ["open redirect", "redirect=", "url=", "next=", "return=", "dest="],
        "title": "🔗 Vulnerability Context: Open Redirect",
        "severity": "Medium",
        "methodology": "• ابحث عن بارامترات التحويل بعد تسجيل الدخول أو الخروج.\n• اختبر التخطي للفلاتر البدائية باستخدام الـ Slashes المزدوجة `///evil.com` أو الأقواس المغلقة `https://target.com@evil.com`.\n• جرب استخدام الـ Payload الخاص بالـ Javascript لتحويل مسار بروتوكولي: `javascript:alert(1)` لتوليد DOM-based XSS.",
        "command": "gau [TARGET] | grep -E '(redirect|url|next|return|dest)=' | qsreplace 'https://evil.com'"
    },
    "vun_idor": {
        "keywords": ["idor", "bola", "broken object level authorization", "/api/v", "id="],
        "title": "🆔 Vulnerability Context: Insecure Direct Object Reference (IDOR / BOLA)",
        "severity": "High to Critical",
        "methodology": "• عند رؤية طلب مخصص لمورد معين (مثل `/api/user/1024` أو `?account_id=980`) قم بتغيير الرقم لمعرف مستخدم آخر.\n• جرب تغيير نوع الطلب: إذا كان المستخدم العادي يقرأ عبر GET، اختبر التعديل عبر PUT/POST أو الحذف عبر DELETE.\n• استخدم معرفات طويلة (UUID) إن أمكن عبر تخمينها من مسارات عامة أخرى داخل التطبيق.",
        "command": "🎯 تكتيك ميداني: استخدم إضافة Autorize في Burp Suite لأتمتة فحص تخطي الصلاحيات بين حسابين بكفاءة."
    },
    "vun_graphql": {
        "keywords": ["graphql", "/graphql", "query {", "mutation", "introspection"],
        "title": "📊 Vulnerability Context: GraphQL API Exploitation",
        "severity": "Low to High",
        "methodology": "• اختبر تفعيل خاصية الـ Introspection لاستخراج خريطة الـ Schema الكاملة للـ API وعزل الـ Queries المخفية.\n• ابحث عن مشاكل الـ Batching Attacks لإرسال مئات الطلبات (مثل تخمين الأكواد) في طلب واحد لتخطي الـ Rate Limiting.\n• افحص ثغرات الـ Field Suggestions لمعرفة الحقول المخفية عند كتابة حقل خاطئ بالعمق.",
        "command": "graphql-cop -u [TARGET]/graphql"
    },
    "vun_sqli": {
        "keywords": ["sqli", "sql injection", "union select", "select ", "order by", "database error"],
        "title": "🛢️ Vulnerability Context: SQL Injection (SQLi)",
        "severity": "High to Critical",
        "methodology": "• اختبر حقن علامات الاقتباس (`'` أو `\"`) لمراقبة حدوث أخطاء بقواعد البيانات (Error-Based).\n• في الحقول غير المستجيبة ظاهرياً، اختبر الـ Time-Based Blind SQLi عبر دوام التأخير مثل `sleep(5)`.\n• افحص ترويسات الطلبات مثل `X-Forwarded-For` أو `User-Agent` فغالباً ما يتم تخزينها داخل قواعد البيانات دون فحص.",
        "command": "sqlmap -u '[URL_WITH_PARAMS]' --batch --banner --risk=3 --level=5"
    },
    "vun_cors": {
        "keywords": ["cors", "cross-origin", "origin:", "access-control-allow-origin", "null origin"],
        "title": "🌐 Vulnerability Context: CORS Misconfiguration",
        "severity": "Medium to High",
        "methodology": "• أرسل طلب يحتوي على الترويسة `Origin: https://evil.com` وراقب الرد.\n• إذا رجع السيرفر الترويسة مصحوبة بـ `Access-Control-Allow-Credentials: true` فهذا يعني تسريب كامل لبيانات الحساب البرمجية.\n• اختبر إرسال `Origin: null` فبعض السيرفرات تثق بالمنشأ الفارغ بشكل خاطئ.",
        "command": "curl -H \"Origin: https://attacker.com\" -I [TARGET]"
    },
    "vun_ssti": {
        "keywords": ["ssti", "server-side template injection", "${{", "{{", "erb", "jinja2", "thymeleaf"],
        "title": "🎨 Vulnerability Context: Server-Side Template Injection (SSTI)",
        "severity": "High to Critical (تؤدي إلى RCE)",
        "methodology": "• ابحث عن الحقول التي تطبع مدخلاتك داخل قوالب ديناميكية (مثل محركات Jinja, Twig, Freemarker).\n• احقن العمليات الرياضية مثل `{{7*7}}` أو `${7*7}` فإذا رجعت النتيجة `49` فالموقع مصاب حتماً.\n• تتبع شجرة المحرك للوصول إلى كلاسات النظام الفعالة لاستدعاء الأوامر وتنفيذ الـ RCE.",
        "command": "🎯 تكتيك الفحص: احقن العمليات الحسابية المتنوعة وتعرف على المحرك عبر أداة tplmap."
    }
}
