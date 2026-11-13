# LinkedIn post

Image: [`docs/assets/linkedin_poster.png`](assets/linkedin_poster.png) (1440×1800, 4:5 portrait).
Every number below comes from `outputs/key_numbers.json`.

---

## English

AI is now finding software vulnerabilities at machine speed. I wanted to know what that means for banks and central banks, so I measured it.

I went through all 405,375 records in the public CVE list and the 1,779 entries in CISA's Known Exploited Vulnerabilities catalogue. Here is what I found:

📈 2.27× more CVEs were published in Jan–Oct 2026 than in the same months of 2025. October 2026 alone had 17,051, four times October 2025. Commercial vendors drove the jump: Chrome ×33, Oracle ×13, Microsoft ×4.

🤖 At least 1,598 CVEs credit an AI system or an AI-native firm. That count doubles about every 4 months, and the bugs AI finds are as severe as the ones humans find.

🛡️ Exploitation is not keeping pace. The share of new CVEs exploited within 180 days fell from 3.9 to 2.6 per 1,000, and only 15 AI-credited CVEs have entered KEV so far, mostly as n-days.

🏦 Zero-days reach banks through shared commercial products like file transfer, mail and perimeter devices. Core banking systems were not the entry point in the 33 financial-sector incidents I reviewed.

🇹🇭 I also built a Monte Carlo model of a stylised Thai-like banking system:
• If AI offensive capacity triples, the annual probability of a systemic payment disruption rises about 5× (4.0–6.8×)
• AI-enabled defence removes 50–75% of that increase
• Vendor concentration adds another 36–64%

The takeaway for supervisors: discovery has sped up much faster than exploitation, and that gap is the window to act. Patch speed, vendor concentration and AI on defence matter more than ever. The paper draws ten implications for central banks.

Everything is open and reproducible: public data only, fixed seeds, and every number written by the code.

📖 Paper: https://thanatchon36.github.io/ai-zeroday-banking/paper/
💻 Code + data: https://github.com/thanatchon36/ai-zeroday-banking
🤗 Dataset: https://huggingface.co/datasets/thanatchon36/ai-zeroday-banking
DOI: 10.5281/zenodo.24184069

Comments and critique are very welcome, especially from people working in bank security and financial supervision.

Views are my own.

#Cybersecurity #AI #Banking #CentralBanking #FinancialStability #SystemicRisk #CVE #ZeroDay #RegTech #Thailand #OpenScience

---

## ภาษาไทย

ตอนนี้ AI หาช่องโหว่ซอฟต์แวร์ได้เร็วระดับเครื่องจักรแล้ว ผมอยากรู้ว่าเรื่องนี้มีความหมายอย่างไรต่อธนาคารและธนาคารกลาง เลยลองวัดดูจากข้อมูลจริง

ผมวิเคราะห์ CVE สาธารณะทั้งหมด 405,375 รายการ และรายการช่องโหว่ที่ถูกโจมตีจริงของ CISA (KEV) อีก 1,779 รายการ ได้ผลดังนี้

📈 ช่วง ม.ค.–ต.ค. 2026 มี CVE ประกาศออกมามากกว่าช่วงเดียวกันของปี 2025 ถึง 2.27 เท่า แค่เดือนตุลาคม 2026 เดือนเดียวก็มี 17,051 รายการ หรือ 4 เท่าของตุลาคม 2025

🤖 มี CVE อย่างน้อย 1,598 รายการที่ให้เครดิตระบบ AI หรือบริษัท AI เป็นผู้ค้นพบ จำนวนนี้เพิ่มเป็นเท่าตัวทุกประมาณ 4 เดือน และช่องโหว่ที่ AI เจอก็รุนแรงพอ ๆ กับที่คนเจอ

🛡️ การโจมตีจริงยังตามไม่ทัน สัดส่วน CVE ใหม่ที่ถูกโจมตีภายใน 180 วันลดลงจาก 3.9 เหลือ 2.6 ต่อ 1,000 รายการ

🏦 ใน 33 เหตุการณ์ของภาคการเงินที่ผมรวบรวม zero-day เข้าถึงธนาคารผ่านซอฟต์แวร์เชิงพาณิชย์ที่ใช้ร่วมกันหลายแห่ง เช่น ระบบส่งไฟล์ อีเมล และอุปกรณ์ด้านหน้าเครือข่าย ไม่ใช่ผ่าน core banking

🇹🇭 ผมสร้างแบบจำลอง Monte Carlo ของระบบธนาคารที่มีโครงสร้างคล้ายไทยแบบจำลองขึ้น (ไม่ใช่ข้อมูลของสถาบันจริงแห่งใด) ผลคือ
• ถ้าขีดความสามารถในการโจมตีด้วย AI เพิ่ม 3 เท่า โอกาสที่ระบบการชำระเงินจะหยุดชะงักในระดับระบบต่อปีจะเพิ่มขึ้นราว 5 เท่า (4.0–6.8 เท่า)
• การใช้ AI ช่วยป้องกันลดส่วนที่เพิ่มขึ้นนี้ได้ 50–75%
• การกระจุกตัวของผู้ให้บริการทำให้ความเสี่ยงเพิ่มอีก 36–64%

ข้อสรุปสำหรับผู้กำกับดูแล: การค้นพบช่องโหว่เร่งตัวเร็วกว่าการโจมตีจริงมาก ช่องว่างนี้คือโอกาสที่ต้องรีบใช้ ความเร็วในการ patch การกระจุกตัวของ vendor และการใช้ AI ฝั่งป้องกันสำคัญกว่าที่เคย บทความสรุปนัยต่อธนาคารกลางไว้ 10 ข้อ

ทุกอย่างเปิดเผยและทำซ้ำได้ ใช้ข้อมูลสาธารณะเท่านั้น ทุกตัวเลขในบทความสร้างจากโค้ด

📖 อ่านบทความ: https://thanatchon36.github.io/ai-zeroday-banking/paper/
💻 โค้ดและข้อมูล: https://github.com/thanatchon36/ai-zeroday-banking
🤗 Dataset: https://huggingface.co/datasets/thanatchon36/ai-zeroday-banking

ยินดีรับทุกความเห็นครับ โดยเฉพาะจากผู้ที่ทำงานด้าน cybersecurity ในธนาคารและการกำกับดูแลภาคการเงิน

ความเห็นในโพสต์นี้เป็นของผมเอง

#Cybersecurity #AI #Banking #CentralBanking #FinancialStability #SystemicRisk #ZeroDay #Thailand
