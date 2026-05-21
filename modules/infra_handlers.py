INFRA_MATRIX = {
    "asn_recon": {
        "keywords": ["asn", "ip", "range", "cidr"],
        "title": "Infrastructure & ASN Recon",
        "methodology": "ASN Recon ليس مجرد IP، هو خريطة لسطح هجوم الشركة بالكامل. ابحث عن النطاقات غير المدارة.",
        "command": "amass intel -asn [ASN] | httpx -title",
        "pro_tip": "الـ ASN يكشف خوادم التطوير (Staging) التي نسي المطورون إغلاقها خلف الـ WAF."
    },
    "sub_takeover": {
        "keywords": ["cname", "takeover", "subdomain"],
        "title": "Subdomain Takeover Intelligence",
        "methodology": "ابحث عن الـ CNAME الذي يشير لخدمة خارجية (GitHub, Heroku) غير موجودة حالياً.",
        "command": "subfinder -d [DOMAIN] | nuclei -t exposures/subdomain-takeover.yaml",
        "pro_tip": "لا تكتفِ بـ CNAME، أحياناً يكون الـ NS (Name Server) هو المفتاح للسيطرة الكاملة."
    }
}
