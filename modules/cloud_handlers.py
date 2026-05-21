# modules/cloud_handlers.py

CLOUD_MATRIX = {
    "cloud_leaks": {
        "keywords": ["s3.amazonaws.com", "storage.googleapis.com", "blob.core.windows.net", "digitaloceanspaces"],
        "title": "☁️ Cloud Recon: Cloud Storage Bucket Detected",
        "severity": "🚨 Critical / High (إذا كانت الصلاحيات خاطئة)",
        "methodology": "• تحقق فوراً من صلاحيات الـ Listing (إذا رجع كود 200، يمكنك رؤية كل الملفات).\n• اختبر صلاحية الرفع العشوائي (PutObject) لتثبيت ملفات خبيثة أو إثبات الأثر الأمني.\n• ابحث عن ملفات الكود المصدري المنسية أو قواعد البيانات المرفوعة كنسخ احتياطية.",
        "command": "aws s3 ls s3://[BUCKET_NAME] --no-sign-request"
    },
    "secrets_git": {
        "keywords": ["github", "gitlab", "gitleaks", "trufflehog", ".git/config"],
        "title": "💻 Source Control: Git Secrets & Hardcoded Credentials",
        "severity": "🚨 Critical (ثغرة اختراق كامل للبيئة)",
        "methodology": "• المطورون يرفعون بالخطأ مفاتيح حيوية (AWS Keys, Database Strings, Slack Webhooks).\n• تفقد المستودعات الشخصية للموظفين في الشركة، فغالباً ما يختبرون أكواد العمل هناك.\n• افحص النطاقات الفرعية بحثاً عن مجلد `.git` مكشوف للعامة يمكن تحميله بالكامل.",
        "command": "gitleaks detect --source . -v"
    }
}
