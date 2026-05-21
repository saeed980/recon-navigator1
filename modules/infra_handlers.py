# modules/infra_handlers.py

INFRA_MATRIX = {
    "vun_ssrf": {
        "keywords": ["ssrf", "server-side request forgery", "localhost", "127.0.0.1", "metadata", "dest="],
        "title": "📡 Vulnerability Context: Server-Side Request Forgery (SSRF)",
        "severity": "High to Critical",
        "methodology": "• ابحث عن بارامترات تستقبل روابط أو ملفات لتقوم بقراءتها بالخلفية.\n• احقن العناوين الداخلية مثل `http://127.0.0.1:80` أو عناوين الميتا داتا السحابية لـ AWS: `http://169.254.169.254/latest/meta-data/`.\n• استخدم أدوات التفاعل الخارجي (Burp Collaborator أو Interactsh) لإثبات وجود Blind SSRF.",
        "command": "🎯 تكتيك الاستغلال السحابي: احقن المسار http://169.254.169.254/latest/meta-data/iam/security-credentials/ لسحب مفاتيح الكلاود الحساسة."
    },
    "vun_xxe": {
        "keywords": ["xxe", "xml external entity", "<!entity", "doctype", "xml", "application/xml"],
        "title": "🧱 Vulnerability Context: XML External Entity (XXE)",
        "severity": "High to Critical",
        "methodology": "• إذا كان التطبيق يستقبل بيانات بصيغة XML، قم بحقن كيان خارجي (External Entity) يشير لملفات النظام السيرفرية.\n• اختبر ثغرات الـ Blind XXE عبر استدعاء ملفات خارجية تجبر السيرفر على الاتصال بخادمك الخاص ممرراً محتويات الملفات المنهوبة بالـ Base64.\n• جرب تغيير نوع المحتوى المتوقع (Content-Type) من JSON إلى XML يدوياً لترى هل يقبله التطبيق بالخلفية أم لا.",
        "command": "🎯 PoC Payload الأساسي:\n<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]>\n<user>&xxe;</user>"
    },
    "vun_lfi": {
        "keywords": ["lfi", "local file inclusion", "path traversal", "../../", "/etc/passwd", "file="],
        "title": "📂 Vulnerability Context: Local File Inclusion (LFI / Path Traversal)",
        "severity": "High to Critical",
        "methodology": "• ابحث عن بارامترات تحميل الصور أو عرض الملفات النصية.\n• احقن تسلسلات المسارات العكسية مثل `../../../../etc/passwd` على سيرفرات اللينكس أو `../../../../windows/win.ini` على الويندوز.\n• جرب استخدام الـ PHP Wrappers المتقدمة مثل `php://filter/convert.base64-encode/resource=index.php` لقراءة الكود المصدري للموقع دون تنفيذه.",
        "command": "gau [TARGET] | grep -E '(file|page|path|src|include|doc)=' | qsreplace '../../../../etc/passwd'"
    },
    "vun_cmd_inject": {
        "keywords": ["cmd injection", "command injection", "; system(", "ping ", "| id", "`id`"],
        "title": "💻 Vulnerability Context: OS Command Injection",
        "severity": "🚨 Critical (اختراق خادم كامل فوراً)",
        "methodology": "• تظهر الثغرة عندما يقوم السيرفر بتمرير مدخلات المستخدم مباشرة لأوامر نظام التشغيل (مثل تشغيل أمر ping أو تحويل صيغ الصور).\n• استخدم فواصل الأوامر التكتيكية مثل `;` أو `|` أو `&&` متبوعة بأمر إثبات الاختراق مثل `id` أو `whoami`.\n• للفحص الأعمى (Blind)، احقن أمر التثبيط والتأخير الزمني: `|| sleep 10 ||` لتلاحظ تأخر استجابة الخادم.",
        "command": "🎯 payloads الفحص الميداني: \n; id \n| id \n`id` \n$(id)"
    },
    "vun_race_cond": {
        "keywords": ["race condition", "concurrency", "parallel requests", "turbo intruder"],
        "title": "⏱️ Vulnerability Context: Race Conditions (ثغرات التزامن الزمني)",
        "severity": "Medium to High",
        "methodology": "• تحدث عندما يعالج السيرفر طلبين متوازيين لنفس المورد في نفس الميلي-ثانية (مثال: سحب رصيد مرتين بنفس الوقت أو استخدام كوبون خصم واحد مرتين بالتزامن).\n• التكتيك هو إرسال مجموعة طلبات ضخمة مكدسة في حزمة شبكية واحدة (Single-packet attack) لتصل للخادم وتنفذ دفعة واحدة.",
        "command": "🎯 تكتيك هندسي: استخدم أداة Turbo Intruder في Burp Suite مع تفعيل خيار concurrent connections وضخ طلبات السحب بالتوازي الصارم."
    },
    "vun_file_upload": {
        "keywords": ["file upload", "multipart/form-data", ".php", ".phtml", "filename="],
        "title": "📁 Vulnerability Context: Unrestricted File Upload",
        "severity": "🚨 Critical (RCE عبر تثبيت شيل)",
        "methodology": "• ابحث عن حقول رفع الملفات واختبر رفع ملفات ذات امتدادات تنفيذية مثل `.php`, `.phtml`, `.aspx`, `.jsp`.\n• اختبر تخطي جدران الفحص والـ Magic Bytes عبر تغيير الـ Content-Type إلى `image/jpeg` مع إبقاء الامتداد التنفيذي.\n• جرب ثغرات التسمية المزدوجة مثل `shell.jpg.php` أو استخدام الحروف الصفرية التموهية `shell.php%00.jpg`.",
        "command": "🎯 تكتيك المحترفين: ارفع ملف صورة يحتوي بالداخل على كود بايثون أو PHP خبيث وافحص مسار الحفظ للملف المرفوع."
    },
    "vun_mass_assign": {
        "keywords": ["mass assignment", "parameter pollution", "is_admin", "role:", "admin\":"],
        "title": "🏗️ Vulnerability Context: Mass Assignment / Parameter Injection",
        "severity": "Medium to High",
        "methodology": "• عند إنشاء حساب أو تعديل الملف الشخصي، راقب الـ JSON المبعوث للسيرفر.\n• احقن يدوياً متغيرات إدارية تخمينية مثل `\"is_admin\": true` أو `\"role\": \"admin\"` أو `\"can_delete\": true`.\n• إذا قام السيرفر بربط طلبك بالـ Model الداخلي مباشرة دون فلترة، فسيتم تصعيد صلاحيات حسابك فوراً للإدارة.",
        "command": "🎯 تكتيك الحقن: أضف متغيرات التحكم بالصلاحيات داخل كتل الـ JSON المرفوعة في طلبات الـ POST."
    },
    "vun_sub_takeover": {
        "keywords": ["subdomain takeover", "nxdomain", "cname", "heroku", "github pages", "aws bucket"],
        "title": "🏴 Vulnerability Context: Subdomain Takeover",
        "severity": "High",
        "methodology": "• ابحث عن النطاقات الفرعية التي ترجع كود خطأ `NXDOMAIN` (النطاق غير موجود ولكن سجل الـ CNAME يشير لخدمة خارجية).\n• إذا كانت الخدمة الخارجية الموجه إليها النطاق الفرعي (مثل Heroku أو GitHub Pages) ملغاة أو متاحة للحجز، يمكنك حجزها باسمك والسيطرة الكاملة على النطاق الفرعي التابع للضحية للقيام بعمليات التصيد وسحب الكوكيز.",
        "command": "subfinder -d [DOMAIN] -silent | dnsx -cname -resp"
    }
}
