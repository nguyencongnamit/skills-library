---
id: database-security
language: ar
dir: rtl
source_revision: "afe376a8"
version: "1.0.0"
title: "أمن قواعد البيانات"
description: "منع حقن SQL وسوء استخدام ORM وتسريب الاعتمادات؛ فرض مستخدمين بأقل صلاحيات وهجرات آمنة"
category: prevention
severity: critical
applies_to:
  - "عند توليد SQL أو سلاسل استعلام خام"
  - "عند توليد شيفرة نماذج / استعلامات ORM"
  - "عند توليد ملفات هجرة قاعدة البيانات"
  - "عند توصيل سلاسل الاتصال أو الـ pooling"
languages: ["sql", "python", "javascript", "typescript", "go", "ruby", "java", "kotlin", "csharp"]
token_budget:
  minimal: 1000
  compact: 1200
  full: 2500
rules_path: "rules/"
related_skills: ["secret-detection", "api-security", "logging-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP SQL Injection Prevention Cheat Sheet"
  - "OWASP Database Security Cheat Sheet"
  - "CWE-89: Improper Neutralization of Special Elements in an SQL Command"
  - "CIS PostgreSQL / MySQL Benchmarks"
---

# أمن قواعد البيانات

## القواعد (لوكلاء الذكاء الاصطناعي)

### دائمًا
- استخدم استعلامات معاملاتية / prepared statements لأي SQL يَمَسّ
  قيمًا يتحكم بها المستخدم. مرِّر القيم كمعاملات، لا عبر دمج/تنسيق
  السلاسل (`%s`، `+`، template literals).
- استخدم واجهة الاستعلام الآمنة في ORM. في SQLAlchemy:
  `session.execute(text(":id"), {"id": user_id})`. في Django: طرق
  ORM، `Model.objects.filter(...)`. في Sequelize / Prisma /
  SQLAlchemy core: بُناة `.where({ ... })`. في Go:
  `db.QueryContext(ctx, "select ... where id = $1", id)`.
- تحقّق أن أسماء الأعمدة / الجداول المعرّفة — التي لا يمكن
  تمريرها كمعاملات — تأتي من allowlist مُحدَّدة في الشيفرة، لا من
  مدخلات المستخدم.
- استخدم مستخدم قاعدة بيانات مخصّصًا لكل تطبيق بأدنى صلاحيات
  ممكنة. تطبيقات الويب التي تقرأ فقط لا ينبغي أن تملك
  `INSERT`/`UPDATE`/`DELETE`. مهام الهجرة تعمل بمستخدم منفصل قادر
  على `DDL`.
- فعّل Row-Level Security (Postgres `CREATE POLICY` / Supabase
  RLS / Azure SQL RLS) للجداول متعدّدة المستأجرين، واضبط سياق
  المستأجر لكل جلسة.
- اسحب اعتمادات قاعدة البيانات من مدير أسرار أو متغير بيئة يُحقَن
  عند البدء — لا من `database.yml` / `.env` مُلتزَم به في المستودع.
  دوِّر الاعتمادات وفق جدول.
- استخدم TLS إلى قاعدة البيانات (`sslmode=require` لـ Postgres،
  `requireSSL=true` لـ MySQL، اتصال مُشفَّر لـ MSSQL). ثبّت CA حيثما
  يدعم الـ driver ذلك.
- لـ Connection pooling حدّ أقصى يلائم `max_connections` لقاعدة
  البيانات، مع ضغط رجوع صحي في التطبيق.

### أبدًا
- لا تدمج مدخلات المستخدم في SQL: `"SELECT * FROM users WHERE
  name='" + name + "'"`. حتى لو "هربتها" بنفسك — لا تُهرّب الـ
  drivers بصورة صحيحة إلا حين تربطها عبر واجهة المعاملات.
- لا تستخدم طرق الاستعلام الخام في ORM (`.raw()`، `.objects.raw()`،
  `.query(text(...))`) مع إدراج f-string لمدخلات المستخدم.
- لا تشغّل أعباء التطبيق بمستخدم قاعدة البيانات الفائق / `root` /
  `postgres` / `sa`. أنشئ مستخدم خدمة.
- لا تعطّل TLS إلى قاعدة البيانات (`sslmode=disable`،
  `useSSL=false`).
- لا تخزن أسرارًا أو PII أو blobs كبيرة في أعمدة JSON دون تشفير
  أثناء الراحة وخطة تدوير مفاتيح.
- لا تشغّل هجرات مدمِّرة (DROP TABLE، DROP COLUMN، ALTER COLUMN
  لتغيير نوع على جداول مأهولة) بشكل مدمج في النشر دون خطة
  expand–contract ونسخة احتياطية مُتحقَّقة قابلة للاستعادة.
- لا تربط مستمع قاعدة بيانات مكشوفًا للإنترنت بلا allowlist؛ تبقى
  قواعد البيانات في شبكة خاصة ويُصل إليها عبر bastion / VPN /
  private link.
- لا تسجّل عبارات SQL كاملة مع القيم المرتبطة على مستوى INFO —
  القيم المرتبطة تكون حسّاسة تقريبًا دائمًا.

### إيجابيات خاطئة معروفة
- أدوات التقارير التي تنفّذ SQL مخصّصًا كتبه محلِّلون تدرج المعرّفات
  شرعًا؛ ينبغي أن تعمل على نسخة قراءة فقط بمستخدم منفصل تحول صلاحياته
  دون أي ضرر.
- بعض الـ ORMs (Django، SQLAlchemy 1.x) تستخدم `%s` كـ *علامات
  معاملات*، لا كعلامات format-string في Python — وذلك آمن.
- استعلامات فحص الصحّة (`SELECT 1`) تافهة بقصد.

## السياق (للبشر)

ظلّ حقن SQL في المرتبة #1 أو #2 في كل OWASP Top 10 على مدى خمسة عشر
عامًا ولم يتزحزح، لأن نمط الإخفاق *سهل افتراضيًا*: أي لغة فيها دمج
سلاسل تسمح بإنتاج استعلام. تولّد مساعدات الذكاء الاصطناعي بسرور شيفرة
"تشتغل في dev" تدرج مدخلات المستخدم — خصوصًا لأعمدة الفرز، والمرشّحات
الديناميكية، والترقيم.

تتزاوج هذه الـ skill طبيعيًّا مع `api-security` (تحرس المسار) ومع
`secret-detection` (تحرس سلسلة الاتصال).

## مراجع

- `rules/sql_injection_sinks.json`
- `rules/orm_safe_patterns.json`
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html).
- [CWE-89](https://cwe.mitre.org/data/definitions/89.html) — حقن SQL.
- [PostgreSQL Row-Level Security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).
