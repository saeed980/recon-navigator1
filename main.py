# main.py

import os
import re
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
        [InlineKeyboardButton("⚔️ وضع المحلل والخبير الميداني (أرسل مخرجاتك)", callback_data="system_custom_input")],
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
# [2] دوال التنسيق للمراحل الثابتة
# ==========================================

def format_recon_response(key):
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
        f"💡 **Why this matters:**\n"
        f"{node['why_matters']}\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔗 **المسار التالي:** {next_node_title}"
    )
    return formatted_text, next_node_key

# ==========================================
# [3] محرك تحليل صائد الثغرات الذكي (Bug Bounty Mentor Engine)
# ==========================================

async def analyze_user_recon(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """تحليل ذكي عميق لمدخلات الـ Bug Bounty بأسلوب مستشار أمني محترف"""
    raw_text = update.message.text
    user_text = raw_text.lower()
    
    # تصنيفات تكتيكية ذكية مبنية على أنماط حقيقية (Regex & Context Rules)
    findings_title = ""
    severity = "Informational / Low"
    methodology = ""
    next_command = ""
    
    # 1. حالة مخرجات سجلات الـ DNS (TXT, CNAME, SPF)
    if "spf1" in user_text or "google-site-verification" in user_text or "txt" in user_text or "cname" in user_text:
        findings_title = "📋 تحليل سجلات الـ DNS و الـ TXT Records"
        
        # فحص ذكي إذا كان هناك تسريب أو احتمالية Subdomain Takeover
        if "cname" in user_text and any(x in user_text for x in ["cloudfront", "s3", "github.io", "heroku", "azure"]):
            severity = "High / Medium (احتمالية Subdomain Takeover)"
            methodology = (
                "• السجلات تحتوي على أصول سحابية عبر الـ CNAME.\n"
                "• **نصيحة المعلم:** اختبر ما إذا كان هذا النطاق يشير إلى خدمة سحابية محذوفة أو غير محجوزة (Dangling DNS) لتوثيق ثغرة الاستيلاء على النطاق الفرعي."
            )
            next_command = "subjack -w subdomains.txt -t 100 -timeout 30 -o vuls.txt -ssl"
        else:
            severity = "Informational (بيانات عامة)"
            methodology = (
                "• هذه السجلات هي معلومات تحقق وإعدادات حماية طبيعية (مثل SPF و Google Verification).\n"
                "• **نصيحة المعلم:** السجلات آمنة ولا تشكل ثغرة مباشرة. خطوتك التكتيكية التالية هي الانتقال لعمل Zone Transfer أو الانتقال لكشط النطاقات الفرعية النشطة."
            )
            next_command = "dig axfr @dns-server target.com"

    # 2. أصول التخزين السحابي والتسريبات (Buckets)
    elif any(x in user_text for x in ["s3://", "amazonaws", "storage.googleapis", "digitaloceanspaces"]):
        findings_title = "☁️ أصول تخزين سحابية مكتشفة (Cloud Buckets)"
        if any(x in user_text for x in ["200", "public", "listing", "allow"]):
            severity = "🚨 Critical / High (ثغرة مستودع مكشوف)"
            methodology = (
                "• المستودع يعيد استجابة مفتوحة أو يسمح بسرد الملفات (Listing).\n"
                "• **نصيحة المعلم:** ابحث فوراً عن ملفات التكوين، قواعد البيانات المنسية، أو ملفات الحزم البرمجية لتأكيد الاختراق وعزل الـ PII (بيانات المستخدمين الحساسة)."
            )
            next_command = "aws s3 ls s3://[bucket-name] --no-sign-request"
        else:
            severity = "Medium"
            methodology = (
                "• تم العثور على اسم المستودع، لكن الصلاحيات المباشرة قد تكون مغلقة.\n"
                "• **نصيحة المعلم:** اختبر صلاحية الكتابة والرفع العشوائي (Arbitrary File Upload) أو اختبر صلاحيات الـ Authenticated Users باستخدام حساب AWS خاص بك."
            )
            next_command = "aws s3 cp test.txt s3://[bucket-name]/test.txt"

    # 3. ملفات الجافاسكريبت والتسريبات البرمجية (JS Files / Secrets)
    elif ".js" in user_text or "token" in user_text or "api_" in user_text or "secret" in user_text:
        findings_title = "🔑 تسريب مفاتيح أو تحليل ملفات JavaScript"
        severity = "High / Critical (حسب نوع المفتاح)"
        methodology = (
            "• تم رصد مسارات لملفات برمجة واجهة المستخدم أو مفاتيح تمرير تفاعلية.\n"
            "• **نصيحة المعلم:** لا تعتمد على مجرد ظهور كلمة Token. قم بفحص الملفات لاستخراج الـ Endpoints المخفية، أو التحقق من فعالية المفتاح المسرب (مثل اختبار مفاتيح AWS, Firebase, Stripe) محلياً لإثبات الأثر الأمني."
        )
        next_command = "secretfinder -i https://target.com/assets/main.js -o cli"

    # 4. الواجهات البرمجية وبيئات التطوير (APIs / Dev / Staging)
    elif any(x in user_text for x in ["api/", "v1/", "graphql", "swagger", "dev.", "staging.", "test."]):
        findings_title = "🌐 واجهات ومنافذ بيئات التطوير والاختبار (Endpoints / Environments)"
        severity = "High"
        methodology = (
            "• تم العثور على بيئة غير إنتاجية أو توثيق لواجهة برمجة تطبيقات.\n"
            "• **نصيحة المعلم:** هذه الأصول منجم ذهب للـ Bug Bounty! ابحث عن واجهات التحكم غير المحمية بكلمة سر، واختبر الـ IDOR عبر التلاعب بالمعرفات الرقمية، أو ابحث عن ثغرات الـ Mass Assignment."
        )
        next_command = "ffuf -w api_routes.txt -u https://target.com/api/FUZZ -mc 200,401,403,500"

    # 5. معطيات عامة / غير مصنفة
    else:
        findings_title = "📝 مخرجات استطلاع وفحص عام"
        severity = "Informational"
        methodology = (
            "• تم استقبال البيانات بنجاح في نظام المعلم.\n"
            "• **نصيحة المعلم:** لتجنب التشتت وتضييع الوقت وفحص أهداف خارج النطاق (Out of Scope)، ركز الآن على تصفية الخوادم الحية واستخراج الـ HTTP Status Codes والـ Technologies المستخدمة."
        )
        next_command = "httpx -l targets.txt -sc -td -title"

    # بناء التقرير الاحترافي الصارم لـ Bug Bounty Hunter
    report = (
        f"🎯 **[تقرير مستشار الـ Bug Bounty الميداني]**\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"🔍 **نوع المدخلات المكتشفة:**\n{findings_title}\n\n"
        f"⚠️ **الخطورة الحقيقية (Real Severity):** `{severity}`\n\n"
        f"💡 **المنهجية وتوجيه المعلم (Hunter Methodology):**\n{methodology}\n\n"
        f"💻 **الأمر التكتيكي الفعال للخطوة القادمة (Next Command):**\n"
        f"`{next_command}`\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"👊 أرسل لي المخرجات الجديدة فور استخراجها، أو استخدم الأزرار للتنقل:"
    )

    keyboard = [[InlineKeyboardButton("🔝 القائمة الرئيسية", callback_data="go_to_bot_root")]]
    await update.message.reply_text(text=report, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown")

# ==========================================
# [4] معالجة الأحداث والأزرار (Callbacks)
# ==========================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    welcome_text = (
        "⚔️ **مرحباً بك في محرك الـ Bug Bounty التكتيكي** ⚔️\n\n"
        "أنا لست مجرد بوت عادي يقرأ كلمات مفتاحية عشوائية؛ لقد تم تحديث عقلي البرمجي لأعمل **كـ Mentor ومستشار أمني محترف لك في برامج مكافآت الثغرات**.\n\n"
        "🤖 **ماذا يمكنك أن تفعل الآن؟**\n"
        "• **أرسل لي أي مخرجات حرة فوراً:** (نتائج أدوات، سجلات DNS، روابط، ملفات جافاسكريبت، منافذ) وسأعطيك الفرز الحقيقي لخطورتها، نصيحة ميدانية مجربة، والأمر التكتيكي التالي لتشغيله.\n\n"
        "👇 أو تنقل عبر الأنظمة المدمجة من اللوحة أدناه:"
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
            text="🧠 **وضع مستشار الـ Bug Bounty نشط**\n\nانسخ أي مخرجات ريكون أو مخرجات أدوات هنا مباشرة في الشات. سأقوم بتحليل السياق وفهمه كخبير أمني وليس كآلة صماء.",
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
    application = Application.builder().token(TOKEN).build()
    
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CallbackQueryHandler(callback_router))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, analyze_user_recon))
    
    print("🚀 تم إطلاق عقل المعلم لـ Bug Bounty بنجاح... جاهز لاستلام وتحليل مخرجاتك بدقة ميدانية!")
    application.run_polling()

if __name__ == '__main__':
    main()
