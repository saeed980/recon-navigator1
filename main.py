# main.py
import os
from telegram.ext import Application, CommandHandler, MessageHandler, filters
from modules.web_handlers import WEB_MATRIX
from modules.infra_handlers import INFRA_MATRIX
from modules.cloud_handlers import CLOUD_MATRIX

# دمج المصفوفات لإنشاء "العقل الموسوعي"
ELITE_MATRIX = {**WEB_MATRIX, **INFRA_MATRIX, **CLOUD_MATRIX}

async def handle_hunt(update, context):
    user_input = update.message.text.lower()
    
    # تحويل البوت إلى "Hunting Mode"
    for key, data in ELITE_MATRIX.items():
        if any(keyword in user_input for keyword in data["keywords"]):
            response = (
                f"🏹 **Target Context: {data['title']}**\n\n"
                f"🔬 **Elite Methodology:**\n{data['methodology']}\n\n"
                f"🛠 **Execution Command:**\n`{data['command']}`\n\n"
                f"🧠 **Pro-Tip:** {data['pro_tip']}"
            )
            await update.message.reply_text(response, parse_mode="Markdown")
            return

    await update.message.reply_text("🔍 لم يتم رصد بصمة معروفة. هل هذا النطاق جديد؟ ابحث عن الـ Subdomain Takeover أو حلل الـ JS Files أولاً.")

# ... (باقي إعدادات البوت كما هي)
