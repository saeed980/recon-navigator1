WEB_MATRIX = {
    "xss_mindset": {
        "keywords": ["xss", "script", "input"],
        "title": "Cross-Site Scripting Strategy",
        "methodology": "لا تركز فقط على الـ Alerts. ابحث عن تسريب الـ Cookies أو الـ CSRF Tokens عبر الـ XSS.",
        "command": "dalfox url [TARGET] --blind [YOUR_COLLABORATOR]",
        "pro_tip": "جرب الـ Mutation XSS؛ فالمتصفحات الحديثة لديها فلاتر لكنها تفشل أمام تغيير هيكلة الـ DOM."
    },
    "idor_mindset": {
        "keywords": ["id=", "user_id", "account", "profile"],
        "title": "IDOR & Access Control Logic",
        "methodology": "IDOR لا يعتمد على الـ ID فقط، بل على استبدال الـ UUID أو الـ Session ID بين حسابين.",
        "command": "autorize (Burp Extension)",
        "pro_tip": "دائماً جرب تغيير الـ HTTP Method من GET إلى PUT/POST/DELETE، فكثيراً ما تُحمى الـ GET فقط."
    }
}
