# main.py
import os
import re
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# استيراد المصانع البرمجية المحدثة
from modules.web_handlers import WEB_MATRIX
from modules.infra_handlers import INFRA_MATRIX
from modules.cloud_handlers import CLOUD_MATRIX

load_dotenv()
TOKEN = os.getenv("TELEGRAM_TOKEN")

def analyze_source_code(text):
    """محلل ذكي للسورس كود الخام والصفحات للكشف عن الثغرات والحمايات"""
    findings = []
    
    # كشف الحمايات وأنظمة الدفاع
    if re.search(r"cloudflare|__cfduid|cf-ray", text, re.IGNORECASE):
        findings.append(("🛡️ Cloudflare WAF", "تم رصد بصمة Cloudflare بالسورس كود. تجنب الفحص العشوائي، وابحث عن الـ Origin IP عبر Shodan/Censys لتخطي الحظر."))
    if re.search(r"imperva|incapsula|visid_incap", text, re.IGNORECASE):
        findings.append(("🛡️ Imperva / Incapsula WAF", "الهدف محمي بواسطة Imperva. استخدم ترويسات متغيرة وتجنب الأنماط الهجومية التقليدية لتفادي حظر الـ IP."))
    if re.search(r"content-security-policy", text, re.IGNORECASE):
        findings.append(("🔒 CSP (Content Security Policy)", "تم رصد سياسة أمان المحتوى. افحص قواعدها عبر c भी csp-evaluator لتحديد ثغرات التخطي مثل تجمعات الـ CDN الموثوقة."))

    # كشف تسريبات السورس كود والأخطاء
    if re.search(r"error|exception|sql\s*syntax|mysql_fetch|uid", text, re.IGNORECASE):
        findings.append(("🛢️ Input Filter / SQL Error Leak", "تسريب خطأ داخلي في السورس كود! هذا يشير لضعف في الفلترة (Input Filter). احقن علامات الاقتباس لفحص الـ SQLi."))
    if re.search(r"secret|api[-_]key|password|bearer|token|credentials", text, re.IGNORECASE):
        findings.append(("🔑 Credentials/Secrets Leak", "تم رصد كلمات مفتاحية تشير لتسريب مفاتيح برمجية حساسة داخل السورس كود. افحص القيم فوراً يدوياً."))
        
    return findings

def hunt_intelligence(user_input):
    """المحرك الاستخباراتي الشامل لمطابقة الـ Recon والـ Vulns"""
    input_lower = user_input.lower()
    
    # 1. أولاً: تشغيل فحص السورس كود التلقائي
    code_leaks = analyze_source_code(user_input)
    leak_report = ""
    if code_leaks:
        leak_report = "\n\n🚨 [تحليل السورس كود المباشر]:\n" + "\n".join([f"• *{f[0]}*: {f[1]}" for f in code_leaks])

    # 2. ثانياً: البحث في المصفوفات الهجومية
    all_matrices = {**WEB_MATRIX, **INFRA_MATRIX, **CLOUD_MATRIX}
    
    for key, data in all_matrices.items():
        for keyword in data["keywords"]:
            if keyword in input_lower:
                return f"{data['title']}\n━━━━━━━━━━━━━━━━━━━━━━\n\n⚠️ الخطورة: {data['severity']}\n\n💡 المنهجية التكتيكية:\n{data['methodology']}\n\n💻 السلاح التنفيذي الشامل:\n`{data['command']}`{leak_report}"
                
    # الرد التكتيكي التلقائي في حال عدم مطابقة الكلمات لمنع الردود الغبية
    return f"📝 أصول استطلاع خام / سورس كود غير مصنف\n━━━━━━━━━━━━━━━━━━━━━━\n\n💡 توجيه الخبير:\n• تم فحص النص/الرابط ولم يطابق كلمة مفتاحية صريحة لثغرة معينة.\n• تكتيكياً: إذا كان هذا النطاق جديداً، ابدأ بـ Subdomain Scraping ومطابقة العلاقات الإعلانية (Analytics Relationships) لبناء الخريطة أولاً.{leak_report}\n\n💻 الأمر المقترح:\n`httpx -l targets.txt -sc -cl -title -td`"

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("⚡ مرحبًا بك في مصفوفة Elite Bug Bounty Hunter. أرسل لي أي رابط، نطاق، ASN، أو سورس كود خام وسأقوم بتحليله تكتيكياً فوراً.")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_text = update.message.text
    await update.message.reply_chat_action("typing")
    response = hunt_intelligence(user_text)
    await update.message.reply_text(response, parse_mode="Markdown")

def main():
    if not TOKEN:
        print("❌ خطأ حرج: لم يتم العثور على TELEGRAM_TOKEN في ملف .env")
        return
    app = Application.builder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    print("🚀 البوت يعمل الآن بكفاءة الخبير النخبوية...")
    app.run_polling()

if __name__ == "__main__":
    main()
