CLOUD_MATRIX = {
    "cloud_golden": {
        "keywords": ["s3", "bucket", "azure", "blob", "aws"],
        "title": "Cloud Bucket Golden Rule",
        "methodology": "البحث عن الـ Bucket ليس الهدف، الهدف هو اكتشاف الـ Environment Variables المسربة بالداخل.",
        "command": "s3scanner --bucket [BUCKET_URL]",
        "pro_tip": "إذا وجدت Bucket مفتوحاً، ابحث فيه عن `config.php` أو `.env`؛ فهي كنز للوصول لـ RCE."
    }
}
