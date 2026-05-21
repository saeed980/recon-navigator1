# main.py

import os
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes

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
    """اللوحة الترحيبية لاختيار النظام المطلوب"""
    keyboard = [
        [InlineKeyboardButton("🗺️ دليل استعراض مراحل الاستطلاع (11 مرحلة)", callback_data="system_recon_home")],
        [InlineKeyboardButton("🌲 محرك اتخاذ القرارات الشجرية (Decision Engine)", callback_data="system_tree_home")]
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
            InlineKeyboardButton("🎯 11. Target Prioritization (النهائية)", callback_data="nav_prioritize")
        ],
        [
            InlineKeyboardButton("🔝 العودة للقائمة الرئيسية للبوت", callback_data="go_to_bot_root")
        ]
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
        [
            InlineKeyboardButton("🔝 القائمة الرئيسية", callback_data="go_to_bot_root")
        ]
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
    """توليد أزرار تدفق العمل السلس للتحكم والتنقل عبر الـ Workflow للمراحل الـ 11"""
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
# [3] معالجة الأوامر والأحداث (Handlers & Callbacks)
# ==========================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """نقطة الترحيب المركزية للمساعد الاستكشافي المزدوج"""
    welcome_text = (
        "⚔️ **مرحباً بك في نظام Recon-Navigator المدمج** ⚔️\n\n"
        "تم دمج قوتين استراتيجيتين في هذا المحرك التفاعلي لمساعدتك ميدانياً:\n\n"
        "🗺️ **1. دليل استعراض مراحل الاستطلاع:**\n"
        "دليل تفصيلي يوجهك خطوة بخطوة عبر مسار تدفق متكامل متسلسل يشرح الأدوات والمنهجيات الحيوية.\n\n"
        "🌲 **2. محرك اتخاذ القرارات الشجرية (Decision Engine):**\n"
        "نظام تفاعلي ذكي يبحث النتيجة التي حصلت عليها عملياً (Input Node) ليعطيك القرار والخطوة التكتيكية المباشرة القادمة (Next Action).\n\n"
        "👇 اختر النظام الذي ترغب بتفعيله الآن لبدء العمل الحركي:"
    )
    await update.message.reply_text(
        text=welcome_text,
        reply_markup=get_welcome_menu(),
        parse_mode="Markdown"
    )

async def callback_router(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """الموجه المركزي الموحد لإدارة كافة الانتقالات والأزرار البرمجية دون تداخل"""
    query = update.callback_query
    await query.answer()
    
    data = query.data

    # أولاً: العودة للجذر الأساسي للبوت
    if data == "go_to_bot_root":
        welcome_text = (
            "⚔️ **نظام Recon-Navigator المركزي** ⚔️\n\n"
            "اختر مسار العمل التكتيكي المطلوب من لوحة التحكم أدناه:"
        )
        await query.edit_message_text(text=welcome_text, reply_markup=get_welcome_menu(), parse_mode="Markdown")
        return

    # ثانياً: واجهة نظام مراحل الاستطلاع الـ 11
    if data == "system_recon_home":
        await query.edit_message_text(
            text="🎛️ **دليل تتبع الـ Workflow ومراحل الاستطلاع الـ 11:**\nاختر المرحلة المناسبة لخطتك الحالية للبدء واستعراض المنهجية:",
            reply_markup=get_navigation_menu(),
            parse_mode="Markdown"
        )
        return

    # ثالثاً: واجهة نظام شجرة القرارات
    if data == "system_tree_home":
        await query.edit_message_text(
            text="🎛️ **قائمة شجرة القرارات التفاعلية (Input Nodes):**\nاختر المرحلة الحالية الحيوية لمعالجة نتائجها الميدانية:",
            reply_markup=get_tree_main_menu(),
            parse_mode="Markdown"
        )
        return

    # رابعاً: معالجة ضغط أزرار استعراض المراحل الـ 11 (المسار المتسلسل)
    if data.startswith("nav_"):
        recon_key = data.replace("nav_", "")
        if recon_key in STRATEGIC_RECON:
            response_text, next_step_key = format_recon_response(recon_key)
            await query.edit_message_text(
                text=response_text,
                reply_markup=get_action_buttons(next_step_key),
                parse_mode="Markdown"
            )
            return

    # خامساً: معالجة اختيار عقدة في شجرة القرارات (Input Node)
    if data.startswith("node_"):
        node_key = data.replace("node_", "")
        if node_key in DECISION_TREE:
            node = DECISION_TREE[node_key]
            text = f"📍 **{node['title']}**\n━━━━━━━━━━━━━━━━━━━━━━\n❓ {node['prompt']}"
            await query.edit_message_text(
                text=text,
                reply_markup=get_decisions_menu(node_key),
                parse_mode="Markdown"
            )
            return

    # سادساً: معالجة اختيار النتيجة النهائية من الشجرة (Decision Node -> Action)
    if data.startswith("dec_"):
        # تفكيك البيانات المسترجعة بشكل دقيق لمعرفة العقدة والقرار المختار
        parts = data.replace("dec_", "").split("_", 1)
        node_key = parts[0] + "_node"
        dec_key = parts[1]
        
        if node_key in DECISION_TREE and dec_key in DECISION_TREE[node_key]["decisions"]:
            decision = DECISION_TREE[node_key]["decisions"][dec_key]
            jump_node = decision["jump_to"]
            jump_node_title = DECISION_TREE[jump_node]["title"]
            
            action_text = (
                f"{decision['next_action']}\n\n"
                f"━━━━━━━━━━━━━━━━━━━━━━\n"
                f"🔗 **المسار التلقائي الموصى به تالياً:** {jump_node_title}"
            )
            
            # أزرار الانتقال الذكي للعقد المقترحة تالياً أو العودة
            keyboard = [
                [InlineKeyboardButton(f"⏭️ الذهاب إلى {jump_node_title.split(':')[0]}", callback_data=f"node_{jump_node}")],
                [InlineKeyboardButton("🎛️ قائمة الشجرة الرئيسية", callback_data="system_tree_home")],
                [InlineKeyboardButton("🔝 القائمة المركزية", callback_data="go_to_bot_root")]
            ]
            
            await query.edit_message_text(
                text=action_text,
                reply_markup=InlineKeyboardMarkup(keyboard),
                parse_mode="Markdown"
            )
            return

# ==========================================
# [4] تشغيل المحرك الرئيسي (Main Entry Point)
# ==========================================

def main():
    """تشغيل وإطلاق محرك البوت المدمج الموحد"""
    application = Application.builder().token(TOKEN).build()
    
    # تسجيل معالجات الأحداث
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CallbackQueryHandler(callback_router))
    
    print("🚀 تم تفعيل بوت الـ Recon-Navigator المدمج بنجاح... جاهز للعمل بكفاءة كاملة!")
    application.run_polling()

if __name__ == '__main__':
    main()
