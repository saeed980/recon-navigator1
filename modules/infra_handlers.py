# modules/infra_handlers.py

INFRA_MATRIX = {
    "inf_asn": {
        "keywords": ["asn", "cidr", "ip range"],
        "title": "🌐 Core Recon: Autonomous System Numbers (ASN)",
        "severity": "Informational (رسم خريطة الهدف العريضة)",
        "methodology": "• امتلاك نطاق الـ ASN يعني امتلاك المساحة الرقمية الكاملة للشركة.\n• لا تفحص موقع ويب واحد، بل اسحب الـ IP Ranges التابعة للـ ASN وابحث عن الأجهزة المنسية.\n• فحص البورتات غير التقليدية على الـ CIDR يوصلك لخوادم التطوير الداخلية (Staging).",
        "command": "amass intel -asn [ASN_NUMBER] -o asn_ips.txt"
    },
    "dns_zone": {
        "keywords": ["zone transfer", "axfr", "dnssec", "bind9"],
        "title": "🗺️ DNS Infrastructure: Zone Transfer Opportunity",
        "severity": "High / Critical (إذا نجح النقل)",
        "methodology": "• خوادم الـ DNS التي تسمح بـ AXFR تسرب خريطة النطاقات الكاملة للشركة دون فحص عشوائي.\n• تحقق من كافة خوادم الأسماء (Name Servers) بشكل منفصل.",
        "command": "dig axfr @ns1.target.com target.com"
    }
}
