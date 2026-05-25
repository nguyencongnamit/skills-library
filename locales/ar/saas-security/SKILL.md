---
id: saas-security
language: ar
dir: rtl
source_revision: "f231fd47"
version: "1.0.0"
title: "أمن تطبيقات SaaS"
description: "كشف الـ tokens والإعدادات الخاطئة والرايات الحمراء الإداريّة لِأبرز منصّات SaaS (GWS، وAtlassian، وNotion، وHubSpot، وSalesforce، وBambooHR، وWorkday، وOdoo، ومنصّات الدردشة، وZoom، وCalendly، وNetSuite)"
category: prevention
severity: critical
applies_to:
  - "عند توصيل مفتاح API أو token OAuth لِـ SaaS داخل الكود"
  - "عند مراجعة connector / webhook / جسر SCIM لِـ SaaS"
  - "عند فرز نشاط مشبوه لِمدير SaaS"
  - "عند تأليف بنية تحتيّة تَعبر بحركة SaaS عبر وكيل"
  - "عند الإجابة على سؤال أمن متعلّق بـ SaaS"
languages: ["*"]
token_budget:
  minimal: 1800
  compact: 2500
  full: 3000
rules_path: "rules/"
related_skills: ["secret-detection", "iam-best-practices", "auth-security", "supply-chain-security"]
last_updated: "2026-05-14"
sources:
  - "Google Workspace Admin SDK security guidance"
  - "Atlassian Cloud Security Best Practices"
  - "Salesforce Security Implementation Guide"
  - "HubSpot Private App authentication docs"
  - "Slack OAuth & token type reference"
  - "Microsoft Teams app permission model"
  - "Zoom App Marketplace security review"
  - "BambooHR API & Single Sign-On hardening"
  - "Workday Integration System Security framework"
  - "NetSuite Token-Based Authentication (TBA) guide"
  - "Notion API integration token model"
  - "Lark/Feishu Open Platform security guidelines"
  - "Calendly Webhook V2 signature spec"
  - "CWE-798: Use of Hard-coded Credentials"
  - "CWE-284: Improper Access Control"
  - "CWE-1392: Use of Default Credentials"
---

# أمن تطبيقات SaaS

## القواعد (لوكلاء الذكاء الاصطناعيّ)

### دائمًا
- خزِّن SaaS API tokens، وأسرار OAuth، ومفاتيح توقيع webhooks،
  وملفّات JSON لِـ service-account في **secrets manager** (Vault،
  وAWS Secrets Manager، وGCP Secret Manager، وDoppler، و1Password
  Connect) — لا inline، ولا `os.Setenv`-من-المصدر، ولا في
  متغيّرات repo الخاصّة بـ CI (فقط `secrets.*`).
- لِتكاملات SaaS **القائمة على OAuth** (Google Workspace، وMicrosoft
  365، وSlack، وAtlassian Cloud، وHubSpot، وZoom، وNotion، وLark،
  وCalendly، وNetSuite OAuth 2.0، وSalesforce Connected Apps):
  ثَبِّت `refresh_token` مُشفَّرًا أثناء السكون، وجَدِّد access
  tokens قبل انتهائها، وضَع client secret في مسار خادم-فقط
  (وليس في حِزَم JS/Mobile).
- لِردود **webhook بـ HMAC** (Slack `X-Slack-Signature`، وCalendly
  V2 `Calendly-Webhook-Signature`، وHubSpot v3
  `X-HubSpot-Signature-v3`، ومنصّات على نمط Stripe، وZoom
  verification token، وHMAC لـ outgoing webhook في Teams، وLark
  `X-Lark-Signature`، وNotion verification token): تَحقَّق من
  التوقيع ونافذة الـ timestamp (افتراضيًّا 5 دقائق) على كلّ طلب
  وارد **قبل** تحليل الـ body أو الوثوق بأيّ حقل.
- ثَبِّت عناوين base URL لِـ SaaS APIs على hostnames إنتاج المُورِّد
  (`api.atlassian.com`، و`api.hubapi.com`، و`api.calendly.com`،
  و`*.zoom.us`، و`slack.com/api`، و`graph.microsoft.com`،
  و`api.bamboohr.com`، و`wd*.myworkday.com`،
  و`*.salesforce.com`/`*.force.com`، و`api.notion.com`،
  و`open.larksuite.com`/`open.feishu.cn`، و`*.netsuite.com`).
  وارفض الردود من hostnames غير متوقَّعة — فهذا يُمسك بمحاولات
  استيلاء على DNS، ومحاولات استيلاء على الحساب عبر وكيل.
- عامِل نقاط نهاية **SCIM** و**directory-sync** على أنّها حسّاسة
  أمنيًّا: استلزم mutual TLS أو JWT bearer مُوقَّعًا، وحَدِّد
  المعدّل، وسَجِّل كلّ كتابة مستخدم/مجموعة في سِنك مقاوم
  للعبث.
- استخدم **scopes أقلّ امتياز** على كلّ تطبيق SaaS تُنشئه.
  Salesforce Connected Apps: تَجنَّب `full`/`refresh_token` إلّا
  لزوم. Slack bot tokens: اذكر فقط الـ scopes التي تَستدعيها.
  Google Workspace OAuth: اطلب
  `.../auth/admin.directory.user.readonly` بدلًا من
  `admin.directory.user` إذا لم تَكتب. HubSpot Private Apps: حدِّد
  فقط مربّعات scope التي تَستدعيها فعلًا.
- افرض **التحقّق الثنائيّ (2SV / MFA)** على كلّ وحدة تحكُّم مدير
  SaaS، **بما في ذلك** حسابات super-admin / org-owner /
  billing-owner. اربط SSO بِـ IdP لديك وعَطِّل تراجع كلمة المرور
  للمدراء.
- استلزم **حسابات خدمة مُكرَّسة وغير مُشتركة** لِتكاملات SaaS من
  نظام إلى نظام. أسماء حسابات الخدمة يجب أن تَرمز إلى الغرض
  (`jira-ingestion-sa`، لا `api-user-3`). عَطِّل الدخول التفاعليّ
  على هذه الحسابات حيث تَسمح المنصّة.
- لِـ Google Workspace خصّيصًا: دَوِّر مفاتيح حسابات الخدمة بـ
  domain-wide delegation كلّ ≤ 90 يومًا، وفَضِّل Workload Identity
  Federation حيث يُدعَم، وَدقِّق نداءات `Admin SDK` في
  Admin Console > Reports.
- لِـ Atlassian (Jira/Confluence) خصّيصًا: فَضِّل **OAuth 2.0
  (3LO) / Atlassian Connect** بِـ `actAsAccountId`؛ ولا تَعد إلى
  API tokens مرتبطة بالمستخدم إلّا عند برمجة أتمتة شخصيّة.
  دَوِّر API tokens لكلّ مستخدم كلّ ≤ 90 يومًا.
- لِـ NetSuite خصّيصًا: فَضِّل **OAuth 2.0** أو **TBA (Token-Based
  Authentication)** مع integration record مُكرَّس؛ ولا تَستخدم
  أبدًا تدفّق تسجيل دخول user/password لِتكاملات النظام.
- لِـ BambooHR / Workday / NetSuite (فئة HRIS/ERP): عامِل كلّ تصدير
  مَجمَّع لِبيانات موظّفين/PII على أنّه **حدّ DLP** — سَجِّل
  الطلب، والـ principal المُصادَق عليه، وعدد الصفوف، والوجهة.
  ونَبِّه على حجم غير معتاد.

### أبدًا
- لا تَكتب بشكل مُصلَّب SaaS API token، أو OAuth client secret، أو
  مفتاح توقيع webhook، أو JSON لِـ service-account داخل المصدر،
  أو صور الحاويات، أو ثنائيّات تطبيقات الموبايل، أو JS من جانب
  العميل. صِيغ tokens التي يَكشفها ملفّ القواعد هذا (مثل
  `xoxb-`، و`xapp-`، و`jira_pat_`، و`pat-na`، و`ya29.`، و`1//`،
  و`sk_live_`) يُجريها المهاجمون مسحًا واسعًا على GitHub العامّ،
  وnpm، وPyPI، وDocker Hub خلال دقائق من الـ push.
- لا تُعطِّل التحقّق من توقيع webhook "للتجربة". كلّ حادثة عامّة
  لاختراق Slack / HubSpot / Zoom / Calendly / Teams / Lark / Notion
  عبر webhook مُزوَّر استَغلّت تكاملًا وصل إلى الإنتاج وفحوصات
  التوقيع مُغلَقة.
- لا تَمنح scope OAuth **super admin** لِـ Google Workspace
  (`https://www.googleapis.com/auth/admin`) لأيّ شيء غير أتمتة
  مُحكَمة الضبط ومملوكة لتقنيّة المعلومات. تَحتاج أكثر حالات
  الاستخدام فقط إلى الأَضْيق `admin.directory.*.readonly`.
- لا تُشارِك **API token شخصيًّا** واحدًا عبر الخدمات لِـ Jira،
  وConfluence، وBambooHR، وWorkday، وNetSuite، أو Notion. فالـ
  tokens المرتبطة بشخص تَرث صلاحيّاته وتَتسرَّب من خلال لابتوبه /
  حسابه على SaaS.
- لا تُعِدّ **عنوان incoming webhook** لـ Slack / Teams / Lark /
  Google Chat يَنشر في قناة أعلى ثقة من مُستهلِكيه. فإن كان
  بإمكان CI bot النشر في `#secops`، فاختراق CI = تصيُّد مباشر
  لـ secops. استخدم بدائل: تطبيقات مُوقَّعة + صلاحيّات نشر لكلّ
  قناة.
- لا تَترك **مشاركة الرابط** في Google Drive / Notion / Confluence
  / Atlassian Cloud / SharePoint على "أيّ شخص لديه الرابط" لمستندات
  تَحوي بيانات عملاء، أو أسرارًا، أو خرائط طريق غير عامّة. اضبط
  سياسة مشاركة المؤسّسة افتراضيًّا على **مُقيَّدة بالنطاق**.
- لا تَثِق بحقل **`From` / `email`** في حُمولة webhook من
  Calendly / HubSpot / Zoom كَهويّة موثوقة. فالتوقيع يُثبت أنّ
  *المُورِّد* أرسل الحُمولة؛ أمّا حقول الـ body فقد تَظلّ من تزويد
  المهاجم (مدعوّ مُزوَّر، أو حقل مُخصَّص يَضعه المهاجم). ابحث عن
  المستخدم عبر مُعرِّفه القانونيّ من جهة الخادم.
- لا تُمرِّر **OAuth refresh tokens** لِـ SaaS بين البيئات
  (dev↔staging↔prod) — يجب أن يكون لكلّ بيئة تطبيق متّصل / عميل
  OAuth خاصّ بها، وإلّا فإنّ اعتمادات الإنتاج تَعيش داخل دائرة
  انفجار dev.
- لا تَثِق بكود **Salesforce Apex / NetSuite SuiteScript / Workday
  Studio / Jira ScriptRunner** المُثبَّت من طرف ثالث دون مراجعة
  أمنيّة. فهي تَعمل بصلاحيّات مُرتفِعة، وهي نَاقل متكرّر لحوادث
  سلسلة توريد SaaS (مثل أنماط استيلاء الحسابات في Salesforce عبر
  AppExchange التي وَثَّقها Salesforce Security 2024).

### إيجابيّات خاطئة معروفة
- **رموز sandbox / مثاليّة** يُقدِّمها المُورِّد في الوثائق
  الرسميّة (مثل Slack `xoxb-XXXXXXX-XXXXXXXX`، وStripe
  `sk_test_…`، وCalendly `eyJ…example…`) — تُطابق التعابير
  النمطيّة لكنّها تَحوي علامات نصّيّة `EXAMPLE` / `XXX` / `test`
  في السياق المحيط.
- `ghp_…` / `gho_…` في وثائق SaaS تابعة لطرف ثالث تَشرح كيفيّة
  ربط GitHub بها — تلك tokens لـ GitHub، ليست tokens لمنصّات
  SaaS، ويُغطّيها `secret-detection`.
- **بريد إلكترونيّ عامّ لِحساب خدمة** لتطبيق منشور على Google
  Marketplace (`*@gserviceaccount.com`) — البريد عامّ؛ أمّا
  مفتاح JSON فهو الحسّاس وحده.
- **OAuth client IDs** لِـ SPAs عامّة على الموبايل / الويب —
  مُصمَّمة لتكون عامّة. أمّا **client secret** المقابل فيجب أن
  يَظلّ خاصًّا؛ نبِّه على الـ secret فقط.

## السياق (للبشر)

أصبح SaaS اليوم الناقل المهيمن لتسريب البيانات. ويُبيِّن سجلّ
حوادث 2023-2025 (Snowflake / سرقة tokens OAuth، وOkta / تسرّب ملفّ
HAR، وإعادة تشغيل token من GitHub إلى Slack، والحركة من Salesforce
عبر Atlassian، وتصيُّد التقويم/الجدولة عبر روابط على نمط
Calendly) ثلاثة أنماط فشل متكرّرة:

1. **تشتُّت Tokens.** تَتراكَم tokens المرتبطة بالأشخاص ورموز
   OAuth refresh عبر المُورِّدين. وكلّ واحد منها اعتماد. ركِّزها
   ودَع كلّها تَنتهي وفق إيقاع منتظم.
2. **مشاركة سيّئة الضبط.** تَميل منصّات SaaS افتراضيًّا إلى
   الراحة ("أيّ شخص لديه الرابط"). فتتسرّب بيانات العملاء،
   ومسارات الصفقات، ومستندات اندماجات/استحواذات، ومخطّطات IAM
   الداخليّة عبر هذه القيم الافتراضيّة أكثر من تسرّبها عبر
   عُيوب الكود.
3. **بقع عمياء على فعل المدير.** التصدير المَجمَّع، ومنح
   الصلاحيّات الجماعيّة، ودوران مفاتيح API، وقفزات SCIM في
   الكتابة على المستخدمين، كلّها مؤشّرات لاستيلاء على الحساب
   أو إساءة من الداخل — لكن فقط إذا كنت تَنظر.

تُعطي ملفّات قواعد JSON لكلّ منصّة في هذا الـ skill مراجِعَ
ذكاء اصطناعيّ:

- **صِيَغ Tokens** — أنماط regex لاكتشاف أسرار SaaS مُصلَّبة وقت
  مراجعة PR.
- **إعدادات خاطئة** — إعدادات محدَّدة لتأكيدها (أو رفضها) عند
  توليد كود تكامل SaaS.
- **رايات حمراء إداريّة** — أشكال استعلامات سجلّ ينبغي أن يَبحث
  عنها SIEM / SOAR / قاعدة كشف.

ملفّات القواعد متعمَّدة الخصوصيّة لكلّ مُورِّد، حتى لا يُوَلِّد
وكلاء الذكاء الاصطناعيّ منطق كشف SaaS "عامًّا" يُغفل هجمات حقيقيّة.
وهي أيضًا صغيرة بما يَكفي ليَحملها بناء توزيع
`SECURITY-SKILLS.md` في فئة `full` دون تفجير ميزانيّة الـ tokens.

## مراجع

- `rules/google_workspace.json` — GWS OAuth، وservice-account، وAdmin SDK
- `rules/google_chat.json` — webhooks وbot tokens لِـ Google Chat
- `rules/atlassian.json` — Jira وConfluence Cloud، وOAuth 2.0 / API tokens
- `rules/notion.json` — tokens تكامل Notion، ومشاركة workspace
- `rules/hubspot.json` — HubSpot Private Apps، وOAuth، وwebhook v3 HMAC
- `rules/salesforce.json` — Connected Apps، وsession tokens، وApex/Flow
- `rules/bamboohr.json` — مفتاح API لِـ BambooHR، وSSO، وتصدير موظّفين
- `rules/workday.json` — Workday ISU، وOAuth، وreport-as-a-service
- `rules/odoo.json` — Odoo XML-RPC / JSON-RPC، وكلمة مرور رئيسيّة
- `rules/microsoft_teams.json` — اعتمادات تطبيق + bot في Teams، وHMAC لـ outgoing webhook
- `rules/slack.json` — tokens bot/user/app/config لـ Slack، وعناوين webhook
- `rules/larksuite.json` — tokens tenant access لِـ Lark/Feishu، وwebhook
- `rules/zoom.json` — Zoom JWT (legacy)، وServer-to-Server OAuth، وwebhook
- `rules/calendly.json` — Calendly PAT، وOAuth، وتوقيع webhook V2
- `rules/netsuite.json` — NetSuite TBA، وOAuth 2.0، ورايات SuiteScript الحمراء
- CWE-798، وCWE-284، وCWE-1392
- OWASP API Security Top 10 (2023) — API2 (مصادقة)، وAPI8 (إعداد خاطئ للأمن)
