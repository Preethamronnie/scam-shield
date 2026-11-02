| System | Tested on | Precision | Recall | F1 |
|---|---|---|---|---|
| Model trained on 2012 SMS | 2012 SMS (held out) | 0.99 | 0.95 | 0.97 |
| Model trained on 2012 SMS | Modern scams | 0.78 | 0.58 | 0.67 |
| Model trained on SMS + modern (5-fold CV) | Modern scams | 0.74 | 0.78 | 0.76 |
| Rules only | Modern scams | 1.00 | 1.00 | 1.00 |
| Full system (model + rules) | Modern scams | 0.94 | 0.92 | 0.93 |

Full system: 3 scams missed, 2 false alarms (out of 36 scams and 28 safe messages).
- Missed: Hi Mum, I dropped my phone in the toilet, this is my new number. Can you send me money urgently? I'll explain later.
- Missed: Dad it's me, I'm in trouble and can't talk. Please transfer Rs 20,000 to this UPI ID right now, don't tell anyone.
- Missed: I am in the army and posted outside the city. I can rent you the flat but first send Rs 10,000 advance through UPI to book it.
- False alarm: Your verification code is 482915. It expires in 10 minutes. If you did not request this, ignore this message.
- False alarm: Out for delivery: your package will arrive today between 2pm and 6pm. The delivery partner may call you.
