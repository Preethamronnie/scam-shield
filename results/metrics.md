| System | Tested on | Precision | Recall | F1 |
|---|---|---|---|---|
| Model trained on 2012 SMS | 2012 SMS (held out) | 0.99 | 0.95 | 0.97 |
| Model trained on 2012 SMS | Modern scams | 0.75 | 0.50 | 0.60 |
| Model trained on SMS + modern (5-fold CV) | Modern scams | 0.84 | 0.80 | 0.82 |
| Rules only | Modern scams | 1.00 | 0.98 | 0.99 |
| Full system (model + rules) | Modern scams | 1.00 | 0.95 | 0.98 |

Full system: 3 scams missed, 0 false alarms (out of 66 scams and 52 safe messages).
- Missed: My crypto mentor helped me earn 40% profit last week. Do you want me to add you to the trading group?
- Missed: Hi, is this Ananya? We were supposed to meet for coffee today.
- Missed: Sorry, wrong number! But you seem nice, where are you from? I'm a fashion designer living in Singapore.
