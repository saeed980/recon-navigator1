# main.py

import os
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes

# استيراد البيانات الاستراتيجية من ملف الإعدادات المنفصل
from config import STRATEGIC_RECON

# تحميل المتغيرات البيئية من ملف .env
load_dotenv()
TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')

if not TOKEN:
    raise ValueError("❌ خطأ حرج: لم يتم العثور على توكن البوت في ملف .env. تأكد من إعداده بشكل صحيح.")

def get_navigation_menu():
    """توليد لوحة ملاحة متقدمة لفرز وتتبع مراحل الاستطلاع الـ 11"""
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
        ]
    ]
    return InlineKeyboardMarkup(keyboard)

def format_recon_response(key):
    """تنسيق المخرجات بالأسلوب الصارم المطلوب لبناء عقل المساعد"""
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

def get_action_buttons(next_key):
    """توليد أزرار تدفق العمل السلس للتحكم والتنقل الفوري عبر الـ Workflow"""
    keyboard = [
        [InlineKeyboardButton("⏭️ تنفيذ الخطوة التالية (Next Action)", callback_data=f"nav_{next_key}")],
        [InlineKeyboardButton("🎛️ العودة إلى لوحة الملاحة الرئيسية", callback_data="nav_home")]
    ]
    return InlineKeyboardMarkup(keyboard)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """الحالة الابتدائية للبوت والترحيب بالمستخدم تكتيكياً"""
    welcome_text = (
        "⚔️ **مرحباً بك في نظام الـ Recon-Navigator المتقدم** ⚔️\n\n"
        "هذا البوت صمم ليكون **مساعدك الاستطلاعي الشخصي (Recon Assistant)**. "
        "بدلاً من تقديم شروحات عشوائية، سيوجهك البوت خطوة بخطوة من البداية وحتى الوصول لـ 'مصفوفة الأهداف العالية الأهمية' "
        "عبر مسار تدفق متكامل ($Workflow\ Chain$).\n\n"
        "🗂️ اختر المرحلة التي تبدأ بها الآن لفتح دليلك العملي المباشر:"
    )
    await update.message.reply_text(
        text=welcome_text,
        reply_markup=get_navigation_menu(),
        parse_mode="Markdown"
    )

async def callback_router(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """موجّه الأحداث الذكي لإدارة الانتقالات السلسة وتعديل الرسائل ديناميكياً"""
    query = update.callback_query
    await query.answer()
    
    if query.data == "nav_home":
        await query.edit_message_text(
            text="🎛️ **لوحة الملاحة والـ Workflow الرئيسية:**\nاختر المرحلة المناسبة لخطتك الحالية للبدء:",
            reply_markup=get_navigation_menu(),
            parse_mode="Markdown"
        )
        return
        
    # استخراج المفتاح البرمجي للمرحلة المطلوبة
    recon_key = query.data.replace("nav_", "")
    
    if recon_key in STRATEGIC_RECON:
        response_text, next_step_key = format_recon_response(recon_key)
        await query.edit_message_text(
            text=response_text,
            reply_markup=get_action_buttons(next_step_key),
            parse_mode="Markdown"
        )

def main():
    """تشغيل وإطلاق محرك البوت المنفصل"""
    application = Application.builder().token(TOKEN).build()
    
    # تسجيل معالجات الأحداث والأوامر
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CallbackQueryHandler(callback_router))
    
    print("🚀 تم تشغيل مشروع Recon-Navigator المنفصل بنجاح وهو جاهز للعمل بالفلسفة الجديدة...")
    application.run_polling()

if __name__ == '__main__':
    main()
