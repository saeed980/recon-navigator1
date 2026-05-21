# main.py

import os
import re
import sys
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes

# محاولة استيراد البيانات الاستراتيجية مع معالجة غياب الملف لتجنب توقف البوت
try:
    from config import STRATEGIC_RECON, DECISION_TREE
except ImportError:
    print("⚠️ تحذير: لم يتم العثور على ملف config.py أو أن السجلات مفقودة! سيتم استخدام لوحة التحليل الحر فقط.")
    STRATEGIC_RECON = {}
    DECISION_TREE = {}

# تحميل المتغيرات البيئية من ملف .env
load_dotenv()
TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')

if not TOKEN:
    print("❌ خطأ حرج: لم يتم العثور على توكن البوت في ملف .env. تأكد من إعداده بشكل صحيح.")
    sys.exit(1)

# ==========================================
# [1] لوحات التحكم والملاحة (Menus & Keyboards)
# ==========================================

def get_welcome_menu():
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
    keyboard = []
    if node_key in DECISION_TREE:
        node = DECISION_TREE[node_key]
        for dec_key, dec_value in node.get("decisions", {}).items():
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
    t = user_text.lower()
    
    # 1. Autonomous System Numbers (ASN)
    if "asn" in t or "as" in t or re.search(r"as\d+", t):
        return (
            "🌐 Autonomous System Numbers (ASN) Reconnaissance",
            "Informational (تحديد النطاق العريض)",
            "• **توجيه المعلم:** رصد أرقام الـ ASN يسمح لك بامتلاك كامل المساحة الرقمية للشركة (IP Blocks). لا تقم بفحص نطاق واحد، بل اسحب نطاقات الـ CIDR كاملة التابعة لهذا الـ ASN للتنقيب عن أجهزة منسية خلف جدران الحماية.\n• **المنهجية المستهدفة:** تجميع الـ IP Ranges ثم تصفيتها والبحث عن خدمات غير تقليدية.",
            "amass intel -asn [ASN_NUMBER] -o asn_ips.txt"
        )
    
    # 2. Microsoft Interrogation (Azure / O365)
    elif any(x in t for x in ["azure", "windows.net", "onmicrosoft", "sharepoint"]):
        return (
            "🏢 Microsoft Interrogation & Infrastructure Mapping",
            "Medium إلى High",
            "• **توجيه المعلم:** أهداف مايكروسوفت السحابية والـ Azure Tenant تمتلك ثغرات خطيرة مثل استنشاق أسماء المستخدمين (User Enumeration) أو العثور على مستودعات Blob عامة غير محمية.",
            "o365recon -d target.com"
        )
        
    # 3. Ad and Analytics Relationships
    elif any(x in t for x in ["ua-", "gtm-", "pub-", "googleanalytics", "adsense", "analytics"]):
        return (
            "📊 Ad and Analytics Relationships & Tracking Data",
            "Informational / Medium",
            "• **توجيه المعلم:** الشركات تضع نفس معرفات تتبع جوجل (Google Analytics ID) على مواقعها الرسمية ومواقعها السرية أو بيئات التطوير غير المدرجة بالنطاقات الفرعية. تتبع المعرف سيقودك فوراً لأصول مجهولة داخل الـ Scope.",
            "python3 get_analytics_relationship.py -u https://target.com"
        )

    # 4. Cloud Recon (S3 Buckets, GCP, Azure)
    elif any(x in t for x in ["s3://", "amazonaws", "storage.googleapis", "digitaloceanspaces", "blob.core.windows.net"]):
        if any(x in t for x in ["200", "public", "listing", "allow"]):
            return (
                "☁️ Cloud Recon (🚨 ثغرة مستودع مكشوف)",
                "🚨 Critical / High",
                "• **توجيه المعلم:** المستودع السحابي مفتوح تماماً للعامة! ابحث فوراً عن تسريبات لملفات المصدر أو ملفات الكوكيز، أو بيانات الهوية الحساسة (PII).",
                "aws s3 ls s3://[Bucket_Name] --no-sign-request"
            )
        else:
            return (
                "☁️ Cloud Recon (مستودع مغلق ظاهرياً)",
                "Medium / Low",
                "• **توجيه المعلم:** على الرغم من أن السرد العام مغلق، اختبر دائماً صلاحية الرفع العشوائي (PutObject) باستخدام حساب AWS مخصص لتثبيت الأثر الأمني.",
                "aws s3 cp test.txt s3://[Bucket_Name]/test.txt"
            )

    # 5. Reverse DNS & Reverse IP
    elif any(x in t for x in ["ptr", "reverse dns", "reverse ip", "timed-out", "open"]):
        return (
            "🔄 Reverse DNS & Port Scan Targets Matrix",
            "Informational",
            "• **توجيه المعلم:** عزل الخوادم الحية والمنافذ المفتوحة (مثل 80, 443) يحدد مسار هجوم الويب الخاص بك. ركز على تصفية التقنيات المستخدمة خلف هذه المنافذ وتجنب تضييع الوقت على المنافذ المغلقة.",
            "httpx -l targets.txt -sc -td -title"
        )

    # 6. GitHub Enumeration & Secrets Leaks
    elif any(x in t for x in ["github", "gitleaks", "trufflehog", "git-"]):
        return (
            "💻 GitHub Enumeration & Source Code Secrets Discovery",
            "🚨 Critical / High",
            "• **توجيه المعلم:** المطورون يرتكبون أخطاء كارثية برفع مفاتيح خاصة في مستودعاتهم العامة أو مستودعات الشركة المنسية على GitHub. ابحث عن ملفات التكوين (`.env`, `config.json`).",
            "gitleaks detect --source . -v"
        )

    # 7. الرد الافتراضي الذكي لمجتمع صائدي الثغرات
    else:
        return (
            "📝 مخرجات فحص وتحليل عامة",
            "Informational",
            "• **توجيه المعلم:** تم استقبال البيانات بنجاح في قاعدة بيانات المستشار الميداني. لتجنب الوقوع في فخ الـ False Positives، اشرع فوراً بتمرير هذه الأصول إلى أداة `httpx` لعزل الخوادم المستجيبة حالياً ومعرفة التقنيات المستخدمة خلفها.",
            "httpx -l targets.txt -sc -td -title"
        )

# ==========================================
# [3] معالجة الرسائل النصية المخصصة (Custom Recon Input)
# ==========================================

async def analyze_user_recon(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        user_text = update.message.text
        title, severity, methodology, next_command = advanced_hunter_classifier(user_text)

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
    except Exception as e:
        print(f"❌ Error in message handler: {e}")

# ==========================================
# [4] معالجة الأحداث والأزرار (Callbacks)
# ==========================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    welcome_text = (
        "⚔️ **مرحباً بك في نظام الـ Bug Bounty Mentor المحترف** ⚔️\n\n"
        "أنا مبرمج ومحدث بالكامل على أحدث منهجيات فحص الاستطلاع المتقدم (Recon).\n\n"
        "👇 اضغط على الزر أدناه وأرسل لي مخرجات أدواتك فوراً في الشات لفرزها تكتيكياً:"
    )
    await update.message.reply_text(text=welcome_text, reply_markup=get_welcome_menu(), parse_mode="Markdown")

async def callback_router(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data

    try:
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
                next_node_key = node.get("chain_next", "asn")
                next_node_title = STRATEGIC_RECON.get(next_node_key, {}).get("title", "النهاية")
                
                response_text = (
                    f"📍 **{node.get('title', '')}**\n━━━━━━━━━━━━━━━━━━━━━━\n\n"
                    f"📋 **الخطوات المنهجية (Methodology):**\n{node.get('methodology', '')}\n\n"
                    f"➡️ **Next Step:**\n{node.get('next_step', '')}\n\n"
                    f"💡 **Why this matters:**\n{node.get('why_matters', '')}\n\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━\n🔗 **المسار التالي التلقائي:** {next_node_title}"
                )
                await query.edit_message_text(text=response_text, reply_markup=get_action_buttons(next_node_key), parse_mode="Markdown")
            return

        if data.startswith("node_"):
            node_key = data.replace("node_", "")
            if node_key in DECISION_TREE:
                node = DECISION_TREE[node_key]
                text = f"📍 **{node.get('title', '')}**\n━━━━━━━━━━━━━━━━━━━━━━\n❓ {node.get('prompt', '')}"
                await query.edit_message_text(text=text, reply_markup=get_decisions_menu(node_key), parse_mode="Markdown")
            return

        if data.startswith("dec_"):
            parts = data.replace("dec_", "").split("_", 1)
            node_key = parts[0] + "_node"
            dec_key = parts[1]
            
            if node_key in DECISION_TREE and dec_key in DECISION_TREE[node_key].get("decisions", {}):
                decision = DECISION_TREE[node_key]["decisions"][dec_key]
                jump_node = decision.get("jump_to", "asn_node")
                jump_node_title = DECISION_TREE.get(jump_node, {}).get("title", "البداية")
                
                action_text = f"{decision.get('next_action', '')}\n\n━━━━━━━━━━━━━━━━━━━━━━\n🔗 **المسار التلقائي الموصى به تالياً:** {jump_node_title}"
                keyboard = [
                    [InlineKeyboardButton(f"⏭️ الذهاب إلى {jump_node_title.split(':')[0]}", callback_data=f"node_{jump_node}")],
                    [InlineKeyboardButton("🎛️ قائمة الشجرة الرئيسية", callback_data="system_tree_home")],
                    [InlineKeyboardButton("🔝 القائمة المركزية", callback_data="go_to_bot_root")]
                ]
                await query.edit_message_text(text=action_text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown")
            return
    except Exception as e:
        print(f"❌ Error in callback router: {e}")

# ==========================================
# [5] تشغيل المحرك الرئيسي (Main Entry Point)
# ==========================================

def main():
    application = Application.builder().token(TOKEN).build()
    
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CallbackQueryHandler(callback_router))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, analyze_user_recon))
    
    print("🚀 تم تشغيل البوت بنجاح ومحصن تماماً ضد أخطاء التوقف الصامت!")
    application.run_polling()

if __name__ == '__main__':
    # main.py

import os
import re
import sys
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes

# محاولة استيراد البيانات الاستراتيجية مع معالجة غياب الملف
try:
    from config import STRATEGIC_RECON, DECISION_TREE
except ImportError:
    STRATEGIC_RECON = {}
    DECISION_TREE = {}

load_dotenv()
TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')

if not TOKEN:
    print("❌ خطأ حرج: لم يتم العثور على توكن البوت في ملف .env.")
    sys.exit(1)

# ==========================================
# [1] لوحات التحكم والملاحة (Menus)
# ==========================================

def get_welcome_menu():
    keyboard = [
        [InlineKeyboardButton("⚔️ وضع المحلل الميداني (أرسل مخرجاتك مباشرة)", callback_data="system_custom_input")],
        [InlineKeyboardButton("🌲 محرك اتخاذ القرارات الشجرية الاستراتيجية", callback_data="system_tree_home")],
        [InlineKeyboardButton("🗺️ دليل خريطة طريق الاستطلاع الـ 11", callback_data="system_recon_home")]
    ]
    return InlineKeyboardMarkup(keyboard)

# ==========================================
# [2] محرك التحليل التقني والاستراتيجي الشامل (The Core Engine)
# ==========================================

def advanced_hunter_classifier(user_text: str):
    """
    محرك ذكي متقدم يقوم بفرز تكنولوجيات الويب ومخرجات الـ Recon بدقة عالية
    تمنع التداخل السياقي (False Positives).
    """
    t = user_text.lower()
    
    # -------------------------------------------------------------
    # أولاً: تصنيف منصات إدارة المحتوى وتكنولوجيات الويب (CMS & Tech Stack) - لمنع الخلط
    # -------------------------------------------------------------
    
    # 1. ووردبريس (WordPress CMS)
    if any(x in t for x in ["wordpress", "wp-", "wp_"]):
        return (
            "🧬 Tech Stack: WordPress CMS Discovery",
            "Informational / Medium (حسب ثغرات الإضافات الملحقة)",
            "• **توجيه المعلم:** الهدف يعمل بنظام WordPress. لا تضيع وقتك في فحص النواة الرئيسية للمنصة، بل صب تركيزك بالكامل على استخراج الإضافات (Plugins) والقوالب (Themes) المنصبة، حيث تقع 90% من ثغرات الـ Web في الـ WordPress هناك (مثل XSS, SQLi, LFI).\n• **المنهجية:** ابحث عن مسارات مثل `/wp-content/plugins/` وفحص ملف الـ `xmlrpc.php` وإمكانية تخمين أسماء المستخدمين.",
            "wpscan --url [TARGET] --enumerate p,t,u --plugins-detection aggressive"
        )
        
    # 2. أنظمة إدارة المحتوى الأخرى (Drupal, Joomla, Magento, Shopify)
    elif any(x in t for x in ["drupal", "joomla", "magento", "shopify", "bitrix", "squarespace"]):
        cms_name = "Shopify/E-Commerce" if "shopify" in t else "Enterprise CMS"
        return (
            f"🛍️ Tech Stack: {cms_name} Platform Detected",
            "Informational / Medium",
            f"• **توجيه المعلم:** رصد منصة `{cms_name}` يعني وجود بنية تحتية مخصصة لإدارة المحتوى أو التجارة الإلكترونية. ابحث عن ثغرات ضبط الإعدادات الخاطئة (Misconfigurations)، النسخ الاحتياطية المتروكة، أو لوحات الإدارة المكشوفة.\n• **المنهجية:** استخدام قوالب Nuclei المخصصة للمنصة المستهدفة لفحص الثغرات الشائعة والـ CVEs المعروفة.",
            "nuclei -u [TARGET] -tags cve,cms,panel"
        )

    # 3. إطارات عمل الـ جافاسكريبت الحديثة (React, Angular, Vue, Next.js)
    elif any(x in t for x in ["react", "angular", "vue.js", "next.js", "nuxt", "svelte", "webpack"]):
        return (
            "⚛️ Tech Stack: Modern Single Page Application (SPA / JS Framework)",
            "Informational (تتطلب فحص ملفات المصدر)",
            "• **توجيه المعلم:** المواقع التي تُبنى باستخدام React أو Angular تقوم بتحميل الكثير من المنطق البرمجي في متصفح العميل (Client-Side). هذا يعني أن ملفات الـ `.js` والـ Source Maps هي منجم ذهب حقيقي لك!\n• **المنهجية:** قم بعمل كشط وتحليل لملفات الجافاسكريبت لاستخراج الـ Endpoints المخفية، مفاتيح الـ API الممررة بالخطأ، ومسارات المطورين السرية.",
            "trufflehog verified --gitleaks أو secretfinder -i [JS_URL]"
        )

    # 4. بيئات ولغات البرمجة الخلفية والخوادم (Backend & Web Servers)
    elif any(x in t for x in ["apache", "nginx", "iis", "tomcat", "node.js", "express", "laravel", "django", "spring boot"]):
        server_tech = "Java/Enterprise Server" if "tomcat" in t or "spring" in t else "Backend Environment"
        return (
            f"💻 Tech Stack: {server_tech} & Web Server Infrastructure",
            "Informational / High (إذا كان الإصدار قديماً)",
            f"• **توجيه المعلم:** تحديد خادم الويب (مثل Nginx أو Apache) أو إطار العمل الخلفي (مثل Spring Boot أو Laravel) هو خطوة ممتازة. ابحث فوراً عن صفحات الخطأ الافتراضية، ومسارات الإدارة المخفية، وثغرات الـ Request Smuggling أو الـ Remote Code Execution (RCE) المرتبطة بالإصدار المستعمل.\n• **المنهجية:** فحص الـ Headers بذكاء ومقارنة البصمات البرمجية.",
            "whatweb -a 3 [TARGET]"
        )

    # 5. جدران حماية تطبيقات الويب (WAF - Cloudflare, Akamai, Incapsula)
    elif any(x in t for x in ["cloudflare", "akamai", "incapsula", "sucuri", "f5 big-ip", "barracuda"]):
        return (
            "🛡️ Infrastructure: Web Application Firewall (WAF) Detected",
            "Informational (حظر تكتيكي)",
            "• **توجيه المعلم:** الهدف محمي خلف جدار حماية (WAF). تشغيل عمليات الفحص الهجومية المكثفة الآن سيؤدي لحظر الـ IP الخاص بك فوراً. تكتيكك الأساسي الآن هو العثور على عنوان الـ IP الحقيقي للخادم (Origin IP) لتخطي الـ WAF والوصول للهدف مباشرة.\n• **المنهجية:** ابحث في سجلات التاريخ لـ DNS (DNS History) أو عبر شهادات SSL القديمة في شيردان لمعرفة الـ IP الحقيقي قبل خلف الـ Proxy.",
            "wafw00f [TARGET] أو shodan search 'ssl:[DOMAIN]'"
        )

    # -------------------------------------------------------------
    # ثانياً: تصنيفات مخرجات الاستطلاع العام (Recon & Infrastructure)
    # -------------------------------------------------------------

    # 6. الـ ASN (تم تعديل الـ Regex ليكون صارماً جداً ولا يلتقط أحرف الكلمات العادية)
    elif "asn" in t or re.search(r"\bas\d{3,}\b", t):
        return (
            "🌐 Autonomous System Numbers (ASN) Reconnaissance",
            "Informational",
            "• **توجيه المعلم:** رصد نطاق الـ ASN يمنحك المساحة الكاملة لملكية الشركة من الـ IP Blocks. قم بسحب شبكات الـ CIDR وفحص الأجهزة المستضافة بشكل مستقل بعيداً عن نطاقات الويب التقليدية لمعرفة الخوادم غير المحمية.",
            "amass intel -asn [ASN_NUMBER] -o asn_ips.txt"
        )
    
    # 7. التخزين السحابي (Cloud Buckets)
    elif any(x in t for x in ["s3://", "amazonaws", "storage.googleapis", "digitaloceanspaces", "blob.core.windows.net"]):
        if any(x in t for x in ["200", "public", "listing", "allow"]):
            return (
                "☁️ Cloud Recon (🚨 ثغرة مستودع سحابي مكشوف للعامة)",
                "🚨 Critical / High",
                "• **توجيه المعلم:** المستودع يسمح بالقراءة العامة أو سرد الملفات! ابحث فوراً عن ملفات الـ Source Code المسربة، قواعد البيانات الاحتياطية، أو معلومات المستخدمين الحساسة لإثبات الأثر الأمني البالغ.",
                "aws s3 ls s3://[Bucket_Name] --no-sign-request"
            )
        else:
            return (
                "☁️ Cloud Recon (مستودع مغلق القراءة)",
                "Low",
                "• **توجيه المعلم:** السرد مغلق، ولكن اختبر دائماً ثغرة الرفع العشوائي (Arbitrary File Upload) باستخدام أداة AWS CLI بحساب مخصص للتحقق من صلاحيات الكتابة.",
                "aws s3 cp test.txt s3://[Bucket_Name]/test.txt"
            )

    # 8. معرفات التتبع (Ad & Analytics)
    elif any(x in t for x in ["ua-", "gtm-", "pub-", "googleanalytics", "analytics"]):
        return (
            "📊 Ad and Analytics Relationships Tracking",
            "Informational / Medium",
            "• **توجيه المعلم:** تتبع معرفات التحليلات المشتركة سيكشف لك المواقع السرية والبيئات التجريبية (Staging) للشركة والتي تحمل نفس الكود الإعلاني، مما يفتح لك أهدافاً جديدة غير مطروقة بالـ Scope.",
            "python3 get_analytics_relationship.py -u [TARGET]"
        )

    # 9. الرد الافتراضي الذكي لأي مخرجات أخرى
    else:
        return (
            "📝 مخرجات استطلاع عامة (Raw Recon Data)",
            "Informational",
            "• **توجيه المعلم:** تم استقبال البيانات. لضمان المنهجية الصحيحة، الخطوة الحالية هي تمرير هذه البيانات عبر أداة الفرز `httpx` للتأكد من استجابة المواقع الحية وعزل الـ Status Codes وعناوين الصفحات قبل اختيار أداة الاختراق المناسبة.",
            "httpx -l targets.txt -sc -td -title"
        )

# ==========================================
# [3] معالجة الرسائل والـ Callbacks
# ==========================================

async def analyze_user_recon(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        user_text = update.message.text
        title, severity, methodology, next_command = advanced_hunter_classifier(user_text)

        report = (
            f"🎯 **[تقرير خبير الـ Bug Bounty الميداني]**\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"🔍 **التقنيات والسياق المكتشف:**\n*{title}*\n\n"
            f"⚠️ **الخطورة التقديرية (Severity):** `{severity}`\n\n"
            f"💡 **توجيه المعلم والمنهجية (Hunter Methodology):**\n{methodology}\n\n"
            f"💻 **الأمر التكتيكي الفعال لتشغيله الآن (Next Command):**\n"
            f"`{next_command}`\n\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"👊 انسخ أي مخرجات ريكون أو تكنولوجيات جديدة، وسأقوم بفرزها لك في ثانية!"
        )

        keyboard = [[InlineKeyboardButton("🔝 العودة للقائمة الرئيسية", callback_data="go_to_bot_root")]]
        await update.message.reply_text(text=report, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown")
    except Exception as e:
        print(f"❌ Error in message handler: {e}")

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    welcome_text = (
        "⚔️ **مرحباً بك في نظام الـ Bug Bounty Mentor الذكي** ⚔️\n\n"
        "لقد تم تحديث عقلي البرمجي بالكامل لامتلاك **قوة فرز شاملة لتكنولوجيات الويب (CMS, WAF, Frameworks, Backend)** ومنع التداخل البرمجي الزائف.\n\n"
        "👇 ارمي لي أي نتائج فحص تكنولوجيات (مثل مخرجات Wappalyzer أو httpx) أو مخرجات طرفية مباشرة:"
    )
    await update.message.reply_text(text=welcome_text, reply_markup=get_welcome_menu(), parse_mode="Markdown")

async def callback_router(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data
    try:
        if data == "go_to_bot_root":
            welcome_text = "⚔️ **نظام التحكم المركزي** ⚔️\n\nاختر مسار العمل المطلوب من الأسفل:"
            await query.edit_message_text(text=welcome_text, reply_markup=get_welcome_menu(), parse_mode="Markdown")
            return
        if data == "system_custom_input":
            await query.edit_message_text(
                text="🧠 **وضع مستشار الـ Bug Bounty المتقدم نشط**\n\nقم بلصق مخرجات التكنولوجيات المكتشفة أو نتائج الأدوات مباشرة في الشات وسأتولى الفرز الاستراتيجي التكتيكي فوراً.",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ تراجع", callback_data="go_to_bot_root")]]),
                parse_mode="Markdown"
            )
            return
    except Exception as e:
        print(f"❌ Error in callback router: {e}")

def main():
    application = Application.builder().token(TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CallbackQueryHandler(callback_router))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, analyze_user_recon))
    
    print("🚀 تم الإطلاق بنجاح! محرك التكنولوجيات الشامل جاهز للعمل...")
    application.run_polling()

if __name__ == '__main__':
    main()
    main()
