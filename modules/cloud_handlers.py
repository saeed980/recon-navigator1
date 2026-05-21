# modules/cloud_handlers.py

CLOUD_MATRIX = {
    "vun_cloud_golden": {
        "keywords": ["s3.amazonaws", "blob.core.windows", "storage.googleapis", "cloud recon", "golden"],
        "title": "☁️ Cloud Recon: Advanced Storage Bucket Exploitation (Golden Rule)",
        "severity": "High to Critical",
        "methodology": "• تكتيك Golden Rule Cloud Recon: عند العثور على أصل سحابي، تحقق فوراً من صلاحيات القراءة العمومية (Listing Permission).\n• اختبر صلاحية الرفع العشوائي (PutObject Attack) لرفع ملفات HTML خبيثة لإثبات وجود الـ Stored XSS أو الـ Takeover.\n• ابحث في المستندات المرفوعة بالدلو السحابي عن ملفات النسخ الاحتياطية لقواعد البيانات ومفاتيح الـ SSH المنسية.",
        "command": "aws s3 ls s3://[BUCKET_NAME] --no-sign-request"
    },
    "vun_oauth_biz": {
        "keywords": ["oauth", "redirect_uri", "business logic", "biz logic", "price", "checkout"],
        "title": "⚖️ Vulnerability: OAuth 2.0 Flaws & Advanced Business Logic",
        "severity": "High to Critical",
        "methodology": "• في الـ OAuth، تلاعب بـ `redirect_uri` لتوجيه كود التحقق لسيرفرك. اختبر التخطي عبر الـ Path Traversal بالمسار الخادع.\n• في ثغرات الـ Business Logic (المنطق البرمجي للمطور): تلاعب بالقيم العددية الحساسة. اختبر شراء المنتجات بوضع كميات سالبة (`-1`) أو تعديل حزم الأسعار داخل طلبات الـ POST النهائية لتخطي بوابات الدفع الحقيقية.",
        "command": "🎯 تكتيك: استخدم ميزة الـ Intercept في Burp Suite لمراقبة وتعديل المتغيرات المالية الحساسة أثناء عملية الـ Checkout."
    },
    "vun_jwt_cmd": {
        "keywords": ["jwt", "json web token", "eyj", "cmd inject", "command injection", "race cond"],
        "title": "🪙 Vulnerability: JWT Tampering & OS Command Injection",
        "severity": "🚨 Critical",
        "methodology": "• إذا عثرت على توكن JWT (يبدأ بـ `eyJ`)، اختبر كسر التوقيع بتغيير خوارزمية التشفير بالـ Header إلى `\"alg\": \"None\"`.\n• لثغرات الـ OS Command Injection: احقن فواصل الأوامر الحركية مثل `;` أو `&&` أو `$()` داخل المدخلات الممررة للأوامر الخلفية للسيرفر.\n• ادمج الفحص بالتزامن الصارم (Race Condition) لتخطي حواجز المنطق البرمجي والـ Rate Limits عبر إرسال الطلبات المكدسة بالتوازي الفوري.",
        "command": "jwt_tool [JWT_TOKEN] -X a"
    }
}
