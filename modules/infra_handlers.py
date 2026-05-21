# modules/infra_handlers.py - تحديث خبير الاستطلاع
INFRA_MATRIX = {
    "recon_suite": {
        "keywords": ["recon", "asn", "whois", "dns", "acquisitions"],
        "title": "Elite Reconnaissance & Asset Mapping",
        "methodology": """
        • **ASN/CIDR:** استخراج النطاق الجغرافي والشبكي (BGP Analysis).
        • **Acquisitions:** تتبع الشركات المستحوذ عليها (مساحة هجومية منسية).
        • **Metadata Sources:** تحليل سجلات DMARC و SPF لكشف النطاقات الداخلية.
        • **Reverse Tactics:** استخدام Reverse DNS/IP لربط الخوادم ببعضها.
        """,
        "command": "amass intel -asn [ASN] -o assets.txt && cat assets.txt | httpx -tech-detect",
        "pro_tip": "ابحث دائماً عن الـ Acquisitions، غالباً ما تكون خوادمها لا تزال مرتبطة بالـ SSO الخاص بالشركة الأم."
    },
    "heat_map_uploads": {
        "keywords": ["upload", "file", "image", "xml"],
        "title": "Heat Map: File Uploads & XML",
        "methodology": "تحليل الـ Metadata داخل الملفات المرفوعة. إذا كان الملف XML، اختبر XXE فوراً. تأكد من الـ Binary Header.",
        "command": "ffuf -w wordlists/files.txt -u [URL]/upload -X POST",
        "pro_tip": "دائماً اختبر الـ SSRF إذا كان الموقع يسمح برفع ملف من رابط خارجي (Remote URL Upload)."
    }
}
