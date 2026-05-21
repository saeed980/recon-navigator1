# modules/web_handlers.py - تحديث المنطق
WEB_MATRIX = {
    "biz_logic": {
        "keywords": ["price", "checkout", "balance", "cart"],
        "title": "Business Logic - The Big Questions",
        "methodology": "هل التطبيق يستخدم RESTful؟ جرب التلاعب بالموارد (`/api/v1/cart/999`) وتغيير الحالة (Status) أو القيم المالية.",
        "command": "Burp Repeater: Change POST body price to -1",
        "pro_tip": "أخطر ثغرات الـ Biz Logic هي التي تظهر في عمليات الـ Checkout (مثلاً: إضافة قسيمة خصم مرتين)."
    },
    "api_analysis": {
        "keywords": ["graphql", "api", "json"],
        "title": "API & GraphQL Heat Mapping",
        "methodology": "APIs هي واجهة التطبيق الحقيقية. ابحث عن نقاط النهاية (Endpoints) غير الموثقة (Undocumented APIs).",
        "command": "nmap --script http-enum,http-methods -p 80,443 [DOMAIN]",
        "pro_tip": "استخدم Burp لجمع الـ API Documentation (Swagger/OpenAPI) فهي خارطة طريق للثغرات."
    }
}
