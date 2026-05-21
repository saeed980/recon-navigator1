# main.py
import os
import sys
import logging
import re
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler, 
    MessageHandler, filters, ContextTypes
)

# استيراد العقول البرمجية من مجلد modules
try:
    from modules.web_handlers import WEB_MATRIX
    from modules.infra_handlers import INFRA_MATRIX
    from modules.cloud_handlers import CLOUD_MATRIX
    
    # دمج كل المصفوفات في عقل تحليلي واحد موحد
    MASTER_RECON_MATRIX = {**WEB_MATRIX, **INFRA_MATRIX, **CLOUD_MATRIX}
except ImportError as e:
    print(f"❌ خطأ حرج أثناء استيراد الملفات من مجلد modules: {e}")
    sys.exit(1)

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()
TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')

if not TOKEN:
    print("❌ خطأ حرج: لم يتم العثور على TELEGRAM_BOT_TOKEN في ملف .env")
    sys.exit(1)

def universal_hunter_analyzer(text_input: str):
    raw_clean = text_input.lower()
    
    # تحصين الـ ASN بشكل صارم عبر الـ Regex
    asn_match = re.search(r"\basn\b|\bas\d{3,}\b", raw_clean)
    
    for key, data in MASTER_RECON_MATRIX.items():
        if key == "inf_asn" and not asn_match:
            continue
        if any(keyword in raw_clean for keyword in data["keywords"]):
            return data["title"], data["severity"], data["methodology"], data["command"]
            
    return (
        "📝 مخرجات استطلاع عامة / أصول خام (Raw Recon Inputs)",
        "Informational",
        "• تم استقبال المخرجات بنجاح وعزل الأصول البرمجية بالداخل.\n• تكتيكياً: مرر هذه القائمة فوراً إلى أداة `httpx` لعزل الخوادم المستجيبة حالياً ومعرفة الـ Status Codes وعناوين الصفحات قبل اختيار السلاح الهجومي التالي.",
        "httpx -l targets.txt -sc -cl -title -td"
    )

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    welcome_text = (
        "⚔️ **مرحباً بك في نظام Bug Bounty Mentor V2 (المعماري الجزئي)** ⚔️\n\n"
        "أنا متصل الآن بـ **العقول البرمجية الفرعية** وجاهز لتحليل أي بيانات ترفعها لي.\n\n"
        "ارمي لي أي مخرجات نصية أو ملفات أدوات مباشرة!"
    )
    await update.message.reply_text(text=welcome_text, parse_mode="Markdown")

async def handle_user_inputs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        user_text = update.message.text
        title, severity, methodology, command = universal_hunter_analyzer(user_text)
        
        report = (
            f"🎯 **[تقرير خبير الـ Bug Bounty الميداني]**\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"🔍 **السياق التكنولوجي المكتشف:**\n*{title}*\n\n"
            f"⚠️ **الخطورة التقديرية للأصل (Severity):** `{severity}`\n\n"
            f"💡 **توجيه المعلم التكتيكي (Hunter Methodology):**\n{methodology}\n\n"
            f"💻 **الأمر الاستراتيجي الفعال لتشغيله الآن:**\n"
            f"`{command}`\n\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"👊 انتظر مخرجات الأداة التالية وشاركها معي فوراً!"
        )
        await update.message.reply_text(text=report, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"Error: {e}")

async def handle_document_outputs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        document = update.message.document
        file = await context.bot.get_file(document.file_id)
        file_bytes = await file.download_as_bytearray()
        file_content = file_bytes.decode('utf-8', errors='ignore')
        
        title, severity, methodology, command = universal_hunter_analyzer(file_content[:5000])
        
        report = (
            f"📁 **[تحليل ملف المخرجات المرفوع: {document.file_name}]**\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"🔍 **السياق المكتشف داخل الملف:**\n*{title}*\n\n"
            f"💡 **التوجيه التكتيكي الفوري:**\n{methodology}\n\n"
            f"💻 **الأمر المقترح لتشغيله الآن:**\n`{command}`\n"
        )
        await update.message.reply_text(text=report, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"Error in document: {e}")

def main():
    application = Application.builder().token(TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_user_inputs))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_document_outputs))
    
    print("🚀 المحرك النظيف متصل بجميع الموديولات وجاهز للعمل الميداني...")
    application.run_polling()

if __name__ == '__main__':
    main()
