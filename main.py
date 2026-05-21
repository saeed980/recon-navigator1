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
    """اللوحة الترحيبية المحدثة لاختيار مسار العمل"""
    keyboard = [
        [InlineKeyboardButton("🧠 تحليل مخصص (أرسل نتائجك نصياً للبوت)", callback_data="system_custom_input")],
        [InlineKeyboardButton("🌲 محرك اتخاذ القرارات الشجرية الجاهزة", callback_data="system_tree_home")],
        [InlineKeyboardButton("🗺️ دليل استعراض مراحل الاستطلاع الـ 11", callback_data="system_recon_home")]
    ]
    return InlineKeyboardMarkup(keyboard)

def get_navigation_menu():
    """لوحة ملاحة متقدمة لفرز وتتبع مراحل الاستطلاع الـ 11"""
    keyboard = [
        [
            InlineKeyboardButton("🌐 1. ASN Recon", callback_data="nav_asn"),
            InlineKeyboardButton("🧬 3. Subdomains", callback_data="nav_subdomains")
        ],
        [
            InlineKeyboardButton("🔎 2. Shodan Hunt", callback_data="nav_shodan"),
            InlineKeyboardButton("🔄 4. Reverse DNS", callback_data="nav_rev_dns")
        ],
        [
            InlineKeyboardButton("📇 5. WHOIS Link", callback_data="nav_whois"),
            InlineKeyboardButton("☁️ 6. Cloud Recon", callback_data="nav_cloud")
        ],
        [
            InlineKeyboardButton("💻 7. GitHub Secrets", callback_data="nav_github"),
            InlineKeyboardButton("📊 8. Tracking ID", callback_data="nav_tracking")
        ],
        [
            InlineKeyboardButton("🏠 9. VHost Fuzz", callback_data="nav_vhost"),
            InlineKeyboardButton("📸 10. Visual Recon", callback_data="nav_screenshot")
        ],
        [
            InlineKeyboardButton("🎯 11. Target Prioritization", callback_data="nav_prioritize")
        ],
        [InlineKeyboardButton("🔝 العودة للقائمة الرئيسية للبوت", callback_data="go_to_bot_root")]
    ]
    return InlineKeyboardMarkup(keyboard)

def get_tree_main_menu():
    """إنشاء لوحة التحكم الرسومية للمراحل الحيوية في شجرة القرارات"""
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
    """توليد أزرار النتائج (Decision Nodes) بناءً على المرحلة الحالية ديناميكياً"""
    node = DECISION_TREE[node_key]
    keyboard = []
    for dec_key, dec_value in node["decisions"].items():
        keyboard.append([InlineKeyboardButton(dec_value["label"], callback_data=f"dec_{node_key}_{dec_key}")])
    keyboard.append([InlineKeyboardButton("🎛️ العودة لقائمة الشجرة الرئيسية", callback_data="system_tree_home")])
    return InlineKeyboardMarkup(keyboard)

def get_action_buttons(next_key):
    """توليد أزرار تدفق العمل السلس للمراحل الـ 11"""
    keyboard = [
        [InlineKeyboardButton("⏭️ تنفيذ الخطوة التالية (Next Action)", callback_data=f"nav_{next_key}")],
        [InlineKeyboardButton("🎛️ العودة إلى لوحة الملاحة الـ 11", callback_data="system_recon_home")]
    ]
    return InlineKeyboardMarkup(keyboard)

# ==========================================
# [2] دوال التنسيق المرجعي للبيانات
# ==========================================

def format_recon_response(key):
    """تنسيق المخرجات بالأسلوب الصارم المطلوب لبناء عقل المساعد للمراحل الـ 11"""
    node = STRATEGIC_RECON[key]
    next_node_key = node["chain_next"]
    next_node_title = STRATEGIC_RECON[next_node_key]["title"]
    
    formatted_text = (
        f"📍 **{node['title']}**\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"📋 **الخطوات المنهجية (Methodology):**\n"
        f"{node['methodology']}\n\n"
        f"➡️ **Next Step (ماذا تفعل الآن):**\n"
        f"{node['next_step']}\n\n"
        f"💡 **Why this matters (أهمية الإجراء والأولوية):**\n"
        f"{node['why_matters']}\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔗 **المسار التالي التلقائي:** {next_node_title}"
    )
    return formatted_text, next_node_key

# ==========================================
# [3] معالجة الرسائل النصية المخصصة (Custom Recon Input)
# ==========================================

async def analyze_user_recon(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """استقبال مخرجات الريكون الحرة من الباحث الأمني وتحليلها تكتيكياً برمجياً"""
    user_text = update.message.text.lower()
    
    # مصفوفة التحليل الذكي للكلمات المفتاحية وعزل الأولويات بناءً على المعطيات المرسلة
    findings = []
    recommendations = []
    priority = "متوسطة"
    next_tool = ""

    if "s3" in user_text or "bucket" in user_text or "blob" in user_text:
        findings.append("🔍 رصد أصول تخزين سحابية (Cloud Buckets/Blobs)")
        if "public" in user_text or "200" in user_text or "list" in user_text:
            priority = "🚨 حرجة جداً (Critical)"
            recommendations.append("• تم اكتشاف صلاحية قراءة عامة! قم فوراً بسحب العينات وتحليلها بحثاً عن ملفات `.env` أو قواعد بيانات.")
            next_tool = "aws s3 cp s3://[bucket-name] . --recursive --no-sign-request"
        else:
            priority = "عالية"
            recommendations.append("• الصلاحيات العامة مغلقة ظاهرياً، اختبر ثغرة الرفع العشوائي والكتابة (PutObject).")
            next_tool = "aws s3 cp test.txt s3://[bucket-name]/test.txt"

    elif "api" in user_text or "graphql" in user_text:
        findings.append("🌐 واجهات برمجية مكشوفة (Endpoints/APIs)")
        priority = "عالية"
        recommendations.append("• اشرع فوراً في عمل كشط وهندسة عكسية للـ Endpoints للبحث عن ثغرات الـ IDOR أو كسر الصلاحيات.")
        next_tool = "ffuf -w api_wordlist.txt -u https://target.com/api/FUZZ -mc 200,401,403"

    elif "git" in user_text or "token" in user_text or "secret" in user_text:
        findings.append("🔑 تسريبات برمجية أو مفاتيح حساسه على GitHub")
        priority = "🚨 حرجة جداً (Critical)"
        recommendations.append("• تم رصد كلمات سر أو مفاتيح في الشيفرة المصدرية؛ تحقق من صلاحية المفاتيح محلياً لتوثيق الاختراق الكامل.")
        next_tool = "gitleaks detect --source . -v"

    elif "dev" in user_text or "staging" in user_text or "test" in user_text:
        findings.append("🖥️ بيئات تطوير واختبار فرعية مكشوفة (Staging/Dev Environments)")
        priority = "عالية"
        recommendations.append("• بيئات التطوير نادراً ما يتم تحديثها؛ ابحث عن ملفات التكوين المنسية أو واجهات الإدارة الخلفية.")
        next_tool = "nuclei -u https://dev.target.com -tags cve,panel"

    elif "shodan" in user_text or "port" in user_text:
        findings.append("🔎 خدمات ومنافذ مفتوحة عبر البنية التحتية")
        priority = "متوسطة إلى عالية"
        recommendations.append("• اعزل المنافذ غير التقليدية (مثل 8080, 8443, 9000) وقم بعمل فرز بصري لمعرفة طبيعة الخدمة.")
        next_tool = "httpx -l IPs.txt -p 80,443,8080,8443 -title"

    else:
        # تحليل عام في حال عدم مطابقة الكلمات السابقة
        findings.append("📝 تم استقبال معطيات استطلاع عامة")
        priority = "متوسطة"
        recommendations.append("• ركز على تصفية هذه الأصول عبر أداة `httpx` لعزل الخوادم الحية المستجيبة ثم ابدأ بالفرز البصري.")
        next_tool = "httpx -l targets.txt -status-code -tech-detect"

    # بناء التقرير الأمني التكتيكي التفاعلي للرد على المستخدم
    report = (
        f"🎯 **[تقرير التحليل الأمني الميداني]**\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"📊 **المدخلات المكتشفة:**\n"
        f"{chr(10).join(findings)}\n\n"
        f"⚠️ **مستوى خطورة الهدف والبروتوكول:** {priority}\n\n"
        f"💡 **توصيات تكتيكية فورية من باحث الويب:**\n"
        f"{chr(10).join(recommendations)}\n\n"
        f"💻 **الأمر المقترح لتشغيله الآن (Next Command):**\n"
        f"`{next_tool}`\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔄 أرسل مخرجات أخرى للمرحلة التالية، أو استخدم القائمة للعودة:"
    )

    keyboard = [[InlineKeyboardButton("🔝 العودة للقائمة الرئيسية", callback_data="go_to_bot_root")]]
    await update.message.reply_text(text=report, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown")

# ==========================================
# [4] معالجة الأحداث والأزرار (Callbacks)
# ==========================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """نقطة الترحيب المركزية للمساعد المحدث"""
    welcome_text = (
        "⚔️ **مرحباً بك في نظام الـ Recon-Navigator المطور** ⚔️\n\n"
        "أنا الآن أعمل **كبـاحث أمني ومختبر اختراق ويب (Web Pentester)** لمساعدتك تكتيكياً:\n\n"
        "🧠 **1. التحليل المخصص الحر:** اضغط على الزر أدناه ثم **أرسل لي أي نتائج أو مخرجات أدوات** حصلت عليها (نصياً) وسأقوم بتحليلها فوراً وأقترح عليك أمر الفحص القادم.\n\n"
        "🌲 **2. محرك القرارات الشجرية:** اتبع مسارات الأسئلة والأجوبة الجاهزة للوصول للأهداف.\n\n"
        "🗺️ **3. دليل المراحل الـ 11:** مرجع متكامل لشرح الأدوات والمنهجيات الحيوية الاستطلاعية."
    )
    await update.message.reply_text(text=welcome_text, reply_markup=get_welcome_menu(), parse_mode="Markdown")

async def callback_router(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """الموجه المركزي الموحد لإدارة الملاحة"""
    query = update.callback_query
    await query.answer()
    data = query.data

    if data == "go_to_bot_root":
        welcome_text = "⚔️ **نظام Recon-Navigator المركزي** ⚔️\n\nاختر مسار العمل التكتيكي المطلوب من لوحة التحكم أدناه:"
        await query.edit_message_text(text=welcome_text, reply_markup=get_welcome_menu(), parse_mode="Markdown")
        return

    if data == "system_custom_input":
        await query.edit_message_text(
            text="🧠 **وضع التحليل الحر نشط الآن!**\n\nقم بكتابة أو نسخ نتائج الاستطلاع الخاصة بك هنا في الشات مباشرة (مثال: نطاقات مكتشفة، روابط S3 Buckets، منافذ مفتوحة من شريحة IPs، إلخ) وسأقوم كباحث أمني بتحليلها وإعطائك الخطوة القادمة.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ تراجع", callback_data="go_to_bot_root")]]),
            parse_mode="Markdown"
        )
        return

    if data == "system_recon_home":
        await query.edit_message_text(
            text="🎛️ **دليل تتبع الـ Workflow ومراحل الاستطلاع الـ 11:**\nاختر المرحلة المناسبة لخطتك الحالية للبدء واستعراض المنهجية:",
            reply_markup=get_navigation_menu(),
            parse_mode="Markdown"
        )
        return

    if data == "system_tree_home":
        await query.edit_message_text(
            text="🎛️ **قائمة شجرة القرارات التفاعلية (Input Nodes):**\nاختر المرحلة الحالية الحيوية لمعالجة نتائجها الميدانية:",
            reply_markup=get_tree_main_menu(),
            parse_mode="Markdown"
        )
        return

    if data.startswith("nav_"):
        recon_key = data.replace("nav_", "")
        if recon_key in STRATEGIC_RECON:
            response_text, next_step_key = format_recon_response(recon_key)
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
    """تشغيل وإطلاق محرك البوت المدمج الموحد"""
    application = Application.builder().token(TOKEN).build()
    
    # تسجيل معالجات الأحداث والأوامر والنصوص
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CallbackQueryHandler(callback_router))
    
    # معالج استقبال الرسائل النصية لتحليل نتائج الريكون الحرة
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, analyze_user_recon))
    
    print("🚀 تم تفعيل محرك الباحث الأمني التفاعلي والتحليل الحر... جاهز لاستقبال بياناتك ميدانياً!")
    application.run_polling()

if __name__ == '__main__':
    main()
