# main.py

import os
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes

# استيراد البيانات الاستراتيجية وشجرة القرارات من ملف config
from config import STRATEGIC_RECON, DECISION_TREE

# تحميل المتغيرات البيئية من ملف .env
load_dotenv()
TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')

if not TOKEN:
    raise ValueError("❌ خطأ حرج: لم يتم العثور على توكن البوت في ملف .env. تأكد من إعداده بشكل صحيح.")

# ==========================================
# [1] لوحات التحكم والملاحة (Menus & Keyboards)
# ==========================================

def get_welcome_menu():
    """اللوحة الترحيبية المركزية لمجتمع Bug Bounty"""
    keyboard = [
        [InlineKeyboardButton("⚔️ وضع المحلل الميداني (أرسل مخرجاتك مباشرة)", callback_data="system_custom_input")],
        [InlineKeyboardButton("🌲 محرك اتخاذ القرارات الشجرية الاستراتيجية", callback_data="system_tree_home")],
        [InlineKeyboardButton("🗺️ دليل خريطة طريق الاستطلاع الـ 11", callback_data="system_recon_home")]
    ]
    return InlineKeyboardMarkup(keyboard)

def get_navigation_menu():
    keyboard = [
        [InlineKeyboardButton("🌐 1. ASN Recon", callback_data="nav_asn"), InlineKeyboardButton("🧬 3. Subdomains", callback_data="nav_subdomains")],
        [InlineKeyboardButton("🔎 2. Shodan Hunt", callback_data="nav_shodan"), InlineKeyboardButton("🔄 4. Reverse DNS", callback_data="nav_rev_dns")],
        [InlineKeyboardButton("📇 5. WHOIS Link", callback_data="nav_whois"), InlineKeyboardButton("☁️ 6. Cloud Recon", callback_data="nav_cloud")],
        [InlineKeyboardButton("💻 7. GitHub Secrets", callback_data="nav_github"), InlineKeyboardButton("📊 8. Tracking ID", callback_data="nav_tracking")],
        [InlineKeyboardButton("🏠 9. VHost Fuzz", callback_data="nav_vhost"), InlineKeyboardButton("📸 10. Visual Recon", callback_data="nav_screenshot")],
        [InlineKeyboardButton("🎯 11. Target Prioritization", callback_data="nav_prioritize")],
        [InlineKeyboardButton("🔝 العودة للقائمة الرئيسية", callback_data="go_to_bot_root")]
    ]
    return InlineKeyboardMarkup(keyboard)

def get_tree_main_menu():
    keyboard = [
        [InlineKeyboardButton("🌐 1. ASN Recon", callback_data="node_asn_node")],
        [InlineKeyboardButton("🧬 2. Subdomain Enum", callback_data="node_subdomains_node")],
        [InlineKeyboardButton("☁️ 3. Cloud Recon", callback_data="node_cloud_node")],
        [InlineKeyboardButton("📸 4. Visual Recon", callback_data="node_screenshot_node")],
        [InlineKeyboardButton("💻 5. GitHub Secrets", callback_data="node_github_node")],
        [InlineKeyboardButton("🔄 6. Reverse DNS", callback_data="node_rev_dns_node")],
        [InlineKeyboardButton("🎯 7. Prioritization Matrix", callback_data="node_prioritize_node")],
        [InlineKeyboardButton("🔝 القائمة الرئيسية", callback_data="go_to_bot_root")]
    ]
    return InlineKeyboardMarkup(keyboard)

def get_decisions_menu(node_key):
    node = DECISION_TREE[node_key]
    keyboard = []
    for dec_key, dec_value in node["decisions"].items():
        keyboard.append([InlineKeyboardButton(dec_value["label"], callback_data=f"dec_{node_key}_{dec_key}")])
    keyboard.append([InlineKeyboardButton("🎛️ العودة لقائمة الشجرة", callback_data="system_tree_home")])
    return InlineKeyboardMarkup(keyboard)

def get_action_buttons(next_key):
    keyboard = [
        [InlineKeyboardButton("⏭️ تنفيذ الخطوة التالية (Next Action)", callback_data=f"nav_{next_key}")],
        [InlineKeyboardButton("🎛️ العودة للملاحة", callback_data="system_recon_home")]
    ]
    return InlineKeyboardMarkup(keyboard)

# ==========================================
# [2] محرك التحليل الاستراتيجي المتقدم لمجتمع الـ Bug Bounty
# ==========================================

def advanced_hunter_classifier(user_text: str):
    """
    محرك ذكي لتحليل مخرجات صيد الثغرات وتصنيفها بناءً على الـ 24 مهارة تكتيكية المتقدمة.
    يعود بـ: (العنوان، مستوى الخطورة، التوجيه المنهجي المخصص، الأمر التالي المقترح)
    """
    t = user_text.lower()
    
    # 1. Autonomous System Numbers (ASN)
    if "asn" in t or "as" in t or re.search(r"as\d+", t):
        return (
            "🌐 Autonomous System Numbers (ASN) Reconnaissance",
            "Informational (تحديد النطاق العريض)",
            "• **توجيه المعلم:** رصد أرقام الـ ASN يسمح لك بامتلاك كامل المساحة الرقمية للشركة (IP Blocks). لا تقم بفحص نطاق واحد، بل اسحب نطاقات الـ CIDR كاملة التابعة لهذا الـ ASN للتنقيب عن أجهزة منسية خلف جدران الحماية.\n• **المنهجية المستهدفة:** تجميع الـ IP Ranges ثم تصفيتها والبحث عن خدمات غير تقليدية.",
            "amass intel -asn [ASN_NUMBER] -o asn_ips.txt"
        )
    
    # 2. Microsoft Interrogation (Azure / O365 / Exchange)
    elif any(x in t for x in ["azure", "windows.net", "onmicrosoft", "sharepoint", "lync"]):
        return (
            "🏢 Microsoft Interrogation & Infrastructure Mapping",
            "Medium إلى High (حسب الثغرة المكتشفة)",
            "• **توجيه المعلم:** أهداف مايكروسوفت السحابية والـ Azure Tenant تمتلك ثغرات خطيرة مثل استنشاق أسماء المستخدمين (User Enumeration) أو العثور على مستودعات Blob عامة غير محمية.\n• **المنهجية المستهدفة:** كشف الـ Active Tenant والتأكد من الصلاحيات المتاحة ومنافذ الـ Exchange المفتوحة.",
            "o365recon -d target.com"
        )
        
    # 3. Ad and Analytics Relationships & Tracking Data
    elif any(x in t for x in ["ua-", "gtm-", "pub-", "googleanalytics", "adsense", "analytics"]):
        return (
            "📊 Ad and Analytics Relationships & Tracking Data",
            "Informational / Medium (كشف الأصول المخفية)",
            "• **توجيه المعلم:** هذه واحدة من أقوى الحيل التكتيكية! الشركات تضع نفس معرفات تتبع جوجل (Google Analytics ID / Tag Manager) على مواقعها الرسمية ومواقعها السرية أو بيئات التطوير غير المدرجة بالنطاقات الفرعية. تتبع المعرف سيقودك فوراً لأصول مجهولة داخل الـ Scope.\n• **المنهجية المستهدفة:** استخدام أدوات أو مواقع هندسة عكسية لمعرفات التتبع لبناء خريطة أصول موحدة.",
            "python3 get_analytics_relationship.py -u https://target.com"
        )
        
    # 4. Acquisitions & Corporate Mapping (WHOIS / Registrant)
    elif any(x in t for x in ["registrant", "organization:", "registrar:", "abuse email"]):
        return (
            "🏢 Acquisitions & Corporate Target Expansion",
            "Informational (توسيع رقعة الهجوم)",
            "• **توجيه المعلم:** إذا كان الموقع الرئيسي محمياً جداً، ابحث عن الشركات التابعة والمستحوذ عليها حديثاً (Acquisitions) من خلال بيانات المسجل في الـ WHOIS. غالباً ما تمتلك هذه الشركات المستحوذة حماية ضعيفة ومكافآتها مقبولة بنفس البرنامج.\n• **المنهجية المستهدفة:** مطابقة اسم المؤسسة أو البريد الإلكتروني للمسؤول لاستخراج نطاقات أخرى تابعة.",
            "bbscope h1 -t [Program_Name] --active"
        )

    # 5. Reverse WHOIS
    elif "reverse whois" in t or "whois lookup" in t:
        return (
            "📇 Reverse WHOIS Discovery",
            "Informational",
            "• **توجيه المعلم:** استخدم اسم الشركة المستهدفة أو بريد مسؤول التسجيل للبحث بالمعكوس عن كل النطاقات المسجلة بهذا الاسم عبر التاريخ.\n• **المنهجية المستهدفة:** تصفية الأهداف الميتة والتركيز على النطاقات الفعالة التابعة للمؤسسة.",
            "whoxy -keyword 'Target Company LLC' --reverse"
        )

    # 6. Cloud Recon featuring Golden (S3 Buckets, GCP, Azure)
    elif any(x in t for x in ["s3://", "amazonaws", "storage.googleapis", "digitaloceanspaces", "blob.core.windows.net"]):
        if any(x in t for x in ["200", "public", "listing", "allow"]):
            return (
                "☁️ Cloud Recon (🚨 ثغرة مستودع مكشوف)",
                "🚨 Critical / High",
                "• **توجيه المعلم:** المستودع السحابي مفتوح تماماً للعامة! ابحث فوراً عن تسريبات لملفات المصدر أو ملفات الكوكيز، أو بيانات الهوية الحساسة (PII).\n• **المنهجية المستهدفة:** التحقق من صلاحية القراءة والكتابة وعزل الأدلة بذكاء دون العبث بالبيانات.",
                "aws s3 ls s3://[Bucket_Name] --no-sign-request"
            )
        else:
            return (
                "☁️ Cloud Recon (مستودع مغلق ظاهرياً)",
                "Medium / Low",
                "• **توجيه المعلم:** على الرغم من أن السرد العام مغلق، اختبر دائماً صلاحية الرفع العشوائي (PutObject) باستخدام حساب AWS مخصص لتثبيت الأثر الأمني.\n• **المنهجية المستهدفة:** اختبار صلاحيات المجموعات الموثقة (Authenticated Users).",
                "aws s3 cp test.txt s3://[Bucket_Name]/test.txt"
            )

    # 7. Reverse DNS & Reverse IP and Domain
    elif "ptr" in t or "reverse dns" in t or "reverse ip" in t:
        return (
            "🔄 Reverse DNS & Reverse IP Target Mapping",
            "Informational / Medium",
            "• **توجيه المعلم:** الفحص العكسي لـ IPs يسحب لك كافة النطاقات المستضافة على نفس السيرفر، مما يمهد لك الطريق لمعرفة إن كان هنالك موقع ويب ضعيف يشارك نفس البنية التحتية ويمكن اختراقه للوصول للهدف.\n• **المنهجية المستهدفة:** عمل مسح شامل لسجلات PTR على شريحة الـ IP المكتشفة.",
            "dnsrecon -r [IP_Range] -t rvs"
        )

    # 8. DMARC Analysis & Demo Course Notes
    elif "dmarc" in t or "_dmarc" in t or "p=none" in t:
        if "p=none" in t:
            return (
                "📧 DMARC Email Security Analysis",
                "Low / Informational (إلا إذا تم إثبات الـ Spoofing)",
                "• **توجيه المعلم:** سياسة `p=none` تعني أن النطاق لا يمنع رسائل البريد المزورة بل يراقبها فقط. بعض البرامج تقبل هذه الثغرة إذا قمت بإثبات إمكانية إرسال بريد مزيف يصل إلى صندوق الوارد الرئيسي (Inbox) مباشرة بدون المرور بالـ Spam.\n• **المنهجية المستهدفة:** فحص سجلات الـ SPF والـ DMARC معاً واختبار الإرسال الفعلي.",
                "spoofcheck.py -d target.com"
            )
        else:
            return (
                "📧 DMARC Email Security Analysis",
                "Informational (محمي)",
                "• **توجيه المعلم:** السجل مضبوط بشكل صحيح على سياسة الحظر (`p=reject` أو `p=quarantine`). هذا يعني أن النطاق محمي بشكل جيد ضد ثغرات الـ Email Spoofing المباشرة. انتقل لفحص الـ Subdomains.",
                "dig txt _dmarc.target.com"
            )

    # 9. Subdomain Scraping & Scraping Secrets (Passive Enum)
    elif any(x in t for x in ["subfinder", "assetfinder", "crt.sh", "certspotter"]):
        return (
            "🧬 Subdomain Scraping & Passive Enumeration",
            "Informational (جمع أصول)",
            "• **توجيه المعلم:** التجميع السلبي (Passive) سريع ولكنه يعطيك النطاقات التي يعرفها الجميع. سر النجاح هنا هو دمج أكثر من 5 مصادر (API Keys) داخل أداة `subfinder` لضمان سحب النطاقات الفرعية العميقة التي لم تظهر للمنافسين.\n• **المنهجية المستهدفة:** تجميع الأصول السلبي تمهيداً لتصفية المواقع الحية وعمل الـ Brute Force عليها تالياً.",
            "subfinder -d target.com -all -recursive -o passive_subs.txt"
        )

    # 10. Subdomain Brute Force & Alteration, Permutation (Active Enum)
    elif any(x in t for x in ["shuffledns", "puredns", "dnsgen", "brute", "permutation", "assetnote"]):
        return (
            "💥 Subdomain Brute Force & Alterations (Active Mode)",
            "Informational / High (إذا اكتشف نطاق سري)",
            "• **توجيه المعلم:** التخمين وتوليد التباديل الذكي (Alterations) باستخدام قاموس `Assetnote` القوي هو السلاح السري للعثور على ثغرات الـ Takeover والـ Dev Panels المنسية التي لا تظهر في سجلات الشهادات العامة (`crt.sh`).\n• **المنهجية المستهدفة:** استخدام أداة مثل `dnsgen` لتوليد الأسماء الذكية بناء على النتائج القديمة وتخمينها عبر محددات DNS سريعة.",
            "dnsgen passive_subs.txt | puredns resolve -r resolvers.txt -o active_brute_subs.txt"
        )

    # 11. GitHub Enumeration & Secrets Leaks
    elif any(x in t for x in ["github", "gitleaks", "trufflehog", "git-"]):
        return (
            "💻 GitHub Enumeration & Source Code Secrets Discovery",
            "🚨 Critical / High",
            "• **توجيه المعلم:** المطورون يرتكبون أخطاء كارثية برفع مفاتيح خاصة في مستودعاتهم العامة أو مستودعات الشركة المنسية على GitHub. ابحث عن ملفات التكوين (`.env`, `config.json`) والمفاتيح الممررة للخدمات.\n• **المنهجية المستهدفة:** الفحص العميق لتاريخ الالتزامات (Commit History) بحثاً عن مفاتيح تم حذفها ظاهرياً ولكنها بقيت في السجلات.",
            "gitleaks detect --source . -v"
        )

    # 12. VHost Scanning (Virtual Hosts)
    elif "vhost" in t or "virtual host" in t or "ffuf -w" in t and "host:" in t:
        return (
            "🏠 Virtual Host (VHost) Scanning & Fuzzing",
            "High / Critical (عند العثور على سيرفر داخلي متاح علناً)",
            "• **توجيه المعلم:** في كثير من الأحيان، خادم الويب يرفض إعطائك لوحة التحكم إذا طلبتها كنطاق فرعي عادي، ولكن عند التلاعب بالـ `Host Header` في الطلب يظن السيرفر أنك قادم من الشبكة الداخلية ويفتح لك الأبواب الخلفية المنسية.\n• **المنهجية المستهدفة:** عمل Fuzzing للـ Host Header ومقارنة حجم الاستجابة (Response Size).",
            "ffuf -w words.txt -u https://target.com -H 'Host: FUZZ.target.com' -fs [Size_To_Ignore]"
        )

    # 13. Screenshotting & Visual Recon
    elif any(x in t for x in ["screenshot", "gowitness", "aquatone", "eyewitness"]):
        return (
            "📸 Screenshotting & Visual Reconnaissance",
            "Informational (منظم وموفر للوقت)",
            "• **توجيه المعلم:** صائد الثغرات المحترف لا يفحص 5000 نطاق فرعي يدوياً بمتصفحه. الفرز البصري التلقائي يساعدك على عزل خوادم الويب المكسورة، لوحات تسجيل الدخول الخاصة بـ Grafana أو Jenkins أو Tomcat، وصفحات الخطأ 404 الجاهزة للـ Takeover بلمحة عين واحدة.\n• **المنهجية المستهدفة:** توليد ألبوم صور تفاعلي لكافة النطاقات الحية وتصنيفها حسب المظهر.",
            "gowitness file -f live_urls.txt"
        )

    # 14. Prioritizing Recon Data & Asset Management
    elif any(x in t for x in ["prioritiz", "matrix", "sorting", "status-code", "open port"]):
        return (
            "🎯 Prioritizing Recon Data & Target Selection Matrix",
            "Informational (تنظيم تكتيكي صارم)",
            "• **توجيه المعلم:** لا تهاجم الموقع عشوائياً. رتب مخرجاتك في مصفوفة أهداف: النطاقات التي تعطي استجابة `403 Forbidden` أو `401 Unauthorized` أو صفحات التطوير المستضافة على منافذ غير تقليدية (مثل 8080, 8443) هي التي تمتلك أعلى أولوية للفحص الفعلي (Fuzzing / Bypass).\n• **المنهجية المستهدفة:** فلترة مخرجات `httpx` والتركيز على أهداف القيمة العالية والتخلي عن الصفحات الساكنة الميتة.",
            "cat httpx_results.txt | grep -E '403|401' > high_priority_targets.txt"
        )

    # 15. Shodan Video / Hunt & Additional Metadata Sources
    elif "shodan" in t or "censys" in t or "zoomeye" in t:
        return (
            "🔎 Advanced Shodan Hunting & Infrastructure Metadata",
            "Medium / High",
            "• **توجيه المعلم:** شيردان يرى خلف الكواليس. استخدم الفلاتر المتقدمة (مثل `ssl.cert.serial` أو `http.html`) للعثور على السيرفرات الحقيقية للشركة التي تختبئ خلف حماية Cloudflare (ثغرة Cloudflare Bypass / Origin IP Leak).\n• **المنهجية المستهدفة:** استجواب الخادم مباشرة عبر عنوان الـ IP الحقيقي وتخطي جدار الحماية للبحث عن ثغرات حركية.",
            "shodan search 'ssl:boardsbeyond.com' --fields ip_str,port,org"
        )

    # 16. الرد الافتراضي الذكي لمجتمع صائدي الثغرات
    else:
        return (
            "📝 مخرجات فحص وتحليل عامة",
            "Informational",
            "• **توجيه المعلم:** تم استقبال البيانات بنجاح في قاعدة بيانات المستشار الميداني. لتجنب الوقوع في فخ الـ False Positives (النتائج الزائفة)، اشرع فوراً بتمرير هذه الأصول إلى أداة `httpx` لعزل الخوادم المستجيبة حالياً ومعرفة التقنيات المستخدمة خلفها قبل اختيار أداة الفحص الهجومي الفعلي.",
            "httpx -l targets.txt -sc -td -title"
        )

# ==========================================
# [3] معالجة الرسائل النصية المخصصة (Custom Recon Input)
# ==========================================

async def analyze_user_recon(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """استقبال مخرجات الريكون ومعالجتها بموجب المحرك الاستراتيجي المتطور لـ Bug Bounty"""
    user_text = update.message.text
    
    # استدعاء المصنف الذكي المحدث للـ 24 مهارة
    title, severity, methodology, next_command = advanced_hunter_classifier(user_text)

    # بناء هيكلية الرد الصارم المعتمد في مجتمع المختبرين المحترفين
    report = (
        f"🎯 **[تقرير خبير الـ Bug Bounty الميداني]**\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"🔍 **سياق الفحص المستهدف:**\n*{title}*\n\n"
        f"⚠️ **الخطورة التقديرية للأصل (Severity):** `{severity}`\n\n"
        f"💡 **توجيه المعلم والمنهجية (Hunter Methodology):**\n{methodology}\n\n"
        f"💻 **الأمر الاستراتيجي الفعال لتشغيله الآن (Next Command):**\n"
        f"`{next_command}`\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"👊 أرسل لي المخرجات القادمة فور خروجها من الطرفية (Terminal)، أو استخدم الأزرار:"
    )

    keyboard = [[InlineKeyboardButton("🔝 العودة للقائمة الرئيسية", callback_data="go_to_bot_root")]]
    await update.message.reply_text(text=report, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown")

# ==========================================
# [4] معالجة الأحداث والأزرار (Callbacks)
# ==========================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    welcome_text = (
        "⚔️ **مرحباً بك في نظام الـ Bug Bounty Mentor المحترف** ⚔️\n\n"
        "أنا الآن جاهز تماماً ومهيأ ومبرمج على **أحدث أدوات ومنهجيات ومفاهيم فحص الاستطلاع المتقدم (Recon)** المستخدمة بواسطة نخبة الباحثين الأمنيين عالمياً.\n\n"
        "🧠 **ما الذي يميز عقلي البرمجي الآن؟**\n"
        "لقد تعلمت وفهمت بعمق كامل تفاصيل خريطة الطريق الحركية:\n"
        "• فحص الـ `ASN` وتجميع الـ `IP Blocks`.\n"
        "• استغلال معرفات التتبع والتحليلات (`Ad & Analytics Relationships`).\n"
        "• فحص الـ `VHost Scanning` وتكتيكات الـ `Alteration & Permutations` لـ `Assetnote`.\n"
        "• تتبع سياق الـ `Reverse WHOIS` والتحقق الذكي لـ `Cloud Recon` و `GitHub Leaks`.\n\n"
        "👇 اضغط على الزر أدناه وأرسل لي مخرجات أدواتك فوراً في الشات لفرزها تكتيكياً:"
    )
    await update.message.reply_text(text=welcome_text, reply_markup=get_welcome_menu(), parse_mode="Markdown")

async def callback_router(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data

    if data == "go_to_bot_root":
        welcome_text = "⚔️ **نظام Recon-Navigator المركزي** ⚔️\n\nاختر مسار العمل التكتيكي المطلوب من لوحة التحكم أدناه:"
        await query.edit_message_text(text=welcome_text, reply_markup=get_welcome_menu(), parse_mode="Markdown")
        return

    if data == "system_custom_input":
        await query.edit_message_text(
            text="🧠 **وضع مستشار ومحلل الـ Bug Bounty المتقدم نشط**\n\nانسخ أي مخرجات ريكون أو مخرجات أدوات أو بيانات أصول هنا مباشرة في الشات. سأقوم فوراً بتحديد سياق المنهجية وإرشادك للأمر التالي الفعال تكتيكياً لتشغيله.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ تراجع", callback_data="go_to_bot_root")]]),
            parse_mode="Markdown"
        )
        return

    if data == "system_recon_home":
        await query.edit_message_text(
            text="🎛️ **دليل تتبع الـ Workflow ومراحل الاستطلاع الـ 11:**",
            reply_markup=get_navigation_menu(),
            parse_mode="Markdown"
        )
        return

    if data == "system_tree_home":
        await query.edit_message_text(
            text="🎛️ **قائمة شجرة القرارات التفاعلية (Input Nodes):**",
            reply_markup=get_tree_main_menu(),
            parse_mode="Markdown"
        )
        return

    if data.startswith("nav_"):
        recon_key = data.replace("nav_", "")
        if recon_key in STRATEGIC_RECON:
            node = STRATEGIC_RECON[recon_key]
            next_node_key = node["chain_next"]
            next_node_title = STRATEGIC_RECON[next_node_key]["title"]
            
            response_text = (
                f"📍 **{node['title']}**\n━━━━━━━━━━━━━━━━━━━━━━\n\n"
                f"📋 **الخطوات المنهجية (Methodology):**\n{node['methodology']}\n\n"
                f"➡️ **Next Step:**\n{node['next_step']}\n\n"
                f"💡 **Why this matters:**\n{node['why_matters']}\n\n"
                f"━━━━━━━━━━━━━━━━━━━━━━\n🔗 **المسار التالي التلقائي:** {next_node_title}"
            )
            await query.edit_message_text(text=response_text, reply_markup=get_action_buttons(next_step_key), parse_mode="Markdown")
            return

    if data.startswith("node_"):
        node_key = data.replace("node_", "")
        if node_key in DECISION_TREE:
            node = DECISION_TREE[node_key]
            text = f"📍 **{node['title']}**\n━━━━━━━━━━━━━━━━━━━━━━\n❓ {node['prompt']}"
            await query.edit_message_text(text=text, reply_markup=get_decisions_menu(node_key), parse_mode="Markdown")
            return

    if data.startswith("dec_"):
        parts = data.replace("dec_", "").split("_", 1)
        node_key = parts[0] + "_node"
        dec_key = parts[1]
        
        if node_key in DECISION_TREE and dec_key in DECISION_TREE[node_key]["decisions"]:
            decision = DECISION_TREE[node_key]["decisions"][dec_key]
            jump_node = decision["jump_to"]
            jump_node_title = DECISION_TREE[jump_node]["title"]
            
            action_text = f"{decision['next_action']}\n\n━━━━━━━━━━━━━━━━━━━━━━\n🔗 **المسار التلقائي الموصى به تالياً:** {jump_node_title}"
            keyboard = [
                [InlineKeyboardButton(f"⏭️ الذهاب إلى {jump_node_title.split(':')[0]}", callback_data=f"node_{jump_node}")],
                [InlineKeyboardButton("🎛️ قائمة الشجرة الرئيسية", callback_data="system_tree_home")],
                [InlineKeyboardButton("🔝 القائمة المركزية", callback_data="go_to_bot_root")]
            ]
            await query.edit_message_text(text=action_text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown")
            return

# ==========================================
# [5] تشغيل المحرك الرئيسي (Main Entry Point)
# ==========================================

def main():
    application = Application.builder().token(TOKEN).build()
    
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CallbackQueryHandler(callback_router))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, analyze_user_recon))
    
    print("🚀 تم دمج الـ 24 مهارة تكتيكية بنجاح! البوت الآن جاهز لتقديم المشورة الأمنية المتقدمة لنخبة الصيادين...")
    application.run_polling()

if __name__ == '__main__':
    main()
