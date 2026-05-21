# modules/infra_handlers.py

INFRA_MATRIX = {
    "rec_asn": {
        "keywords": ["asn", "asnum", "bgp", "cidr", "ip range"],
        "title": "🌐 Advanced Recon: Autonomous System Numbers (ASN) & Core Infrastructure",
        "severity": "Informational (رسم المساحة الرقمية الكاملة)",
        "methodology": "• تكتيك الخبراء (Assetnote): لا تحصر نفسك بنطاق واحد، استخرج الـ ASN للشركة المستهدفة لمعرفة كل نطاقات الـ IPs المملوكة لها.\n• افحص الـ CIDR Ranges المستخرجة للبحث عن الأجهزة المنسية والأنظمة الخلفية وأنظمة التطوير غير المحمية بـ WAF.\n• طابق الـ ASN مع قواعد البيانات العالمية للتأكد من عدم خروج خوادم حيوية من حسابات الحماية.",
        "command": "amass intel -asn [ASN_NUMBER] -o asn_ips.txt && bgpview [ASN]"
    },
    "rec_sub_scraping": {
        "keywords": ["subdomain", "scraping", "subfinder", "assetnote", "nbk", "linked discovery", "acquisitions"],
        "title": "🏴 Advanced Recon: Subdomain Scraping, Brute Force & Alterations",
        "severity": "Informational (بناء الأهداف الهجومية)",
        "methodology": "• منهجية Recon Royale (NBK & Eric): اجمع الأصول عبر الأدوات السلبية (Subfinder, PassiveTotal).\n• قم بعمل Linked Discovery ومطابقة العلاقات الإعلانية (Ad and Analytics Relationships) عبر أداة BuiltWith لكشف المواقع التابعة لنفس المالك والشركات المستحوذ عليها حديثاً (Acquisitions).\n• نفذ الـ Alteration & Permutation (توليد أسماء النطاقات المتقاطعة مثل sub-dev, sub-staging) بناءً على قواميس Assetnote الفعالة.",
        "command": "subfinder -d [DOMAIN] -all -silent | anew subs.txt && halo -t subs.txt"
    },
    "rec_reverse_recon": {
        "keywords": ["reverse whois", "reverse dns", "reverse ip", "dmarc analysis", "metadata"],
        "title": "🔍 Advanced Recon: Reverse Inversions & DMARC Metadata Analysis",
        "severity": "Informational",
        "methodology": "• استخدم Reverse WHOIS للبحث عن جميع النطاقات المسجلة بنفس البريد الإلكتروني للشركة.\n• قم بعمل Reverse DNS لكتل الـ IP المستخرجة من الـ ASN لتحديد أسماء الخوادم الحقيقية الحيوية.\n• حلل سجلات الـ DMARC والـ SPF؛ غالباً ما تسرب هذه السجلات نطاقات داخلية تابعة للشركة أو خوادم اختبار خارجية منسية.",
        "command": "dnsx -ptr -l asn_ips.txt -silent && checkdmarc [DOMAIN]"
    },
    "rec_vhost_screen": {
        "keywords": ["vhost", "virtual host", "screenshot", "screenshotting", "prioritizing"],
        "title": "📸 Advanced Recon: VHost Scanning & Visual Prioritizing",
        "severity": "Informational (تحديد الأهداف الحيوية)",
        "methodology": "• فحص الـ Virtual Hosts (VHost Scanning) يكشف عن مواقع إلكترونية تعيش على نفس السيرفر ولكن ليس لها سجلات DNS عامة.\n• استخدم أدوات الـ Screenshotting (مثل gowitness) لأتمتة تصوير مئات المواقع الفرعية بصرياً.\n• رتب البيانات (Prioritizing Recon Data): ركز فوراً على لوحات التحكم (Admin Panels)، صفحات الخطأ، وبيئات الـ Staging المعزولة للبدء بحقن الـ SSRF فوراً.",
        "command": "ffuf -w wordlists/vhosts.txt -u https://[TARGET] -H 'Host: FUZZ.target.com' -fs [SIZE_OF_404]"
    },
    "vun_ssrf_lfi": {
        "keywords": ["ssrf", "lfi", "local file inclusion", "path traversal", "microsoft interrogation"],
        "title": "📡 Vulnerability: Prioritizing Recon Data + SSRF & LFI",
        "severity": "High to Critical",
        "methodology": "• ابحث في الأصول المستخرجة من الفحص البصري عن روابط تستقبل روابط مدخلة.\n• تكتيك Microsoft Interrogation: افحص خوادم مايكروسوفت والأنظمة الداخلية المحيطة بها لاستغلال الـ SSRF للوصول للخدمات الحيوية الداخلية وخوادم الميتا داتا السحابية.\n• في حالات الـ LFI، احقن الـ PHP Wrappers لقراءة الكود المصدري للموقع بشكل صريح دون تنفيذه لبدء كشف الـ Hardcoded Credentials.",
        "command": "gau [TARGET] | grep -E '(url|file|path|dest|source)=' | qsreplace 'http://169.254.169.254/latest/meta-data/'"
    }
}
