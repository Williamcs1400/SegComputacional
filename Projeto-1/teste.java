public class teste {
    
    public static String prob(String str)
         {
             str = str.toLowerCase();
             int [] count = new int [26];
             int n = 0;
             for (int i=0;i<str.length();i++)
             {
                 int val = str.charAt(i) - 'a';
                 if (val >= 0 && val <= 25)
                 {
                     count[val] = count[val] + 1;
                     n++;
                 }
             }
             double total = 0;
             for (int i = 0; i < count.length ; i++)
             {
                 total += count[i] * (count[i]- 1);
             }
             total = total/n/(n-1);
             String result="IC is: " + total;
             Integer nchars=1;
             if (total >= 0.0660) nchars = 1;
             else if (total >= 0.0520) nchars = 2;
             else if (total >= 0.0473) nchars = 3;
             else if (total >= 0.0449) nchars = 4;
             else if (total >= 0.0435) nchars = 5;
             else if (total >= 0.0426) nchars = 6;
             else if (total >= 0.0419) nchars = 7;
             else if (total >= 0.0414) nchars = 8;
             else if (total >= 0.0410) nchars = 9;
             else if (total >= 0.0407) nchars = 10;
             else nchars = 0;
             result += "\nPredicted characters in password is: " + nchars.toString();
             return (result);
         }
         
    public static void main(String args[]) {
      String s = "LLM REYIVWNA GQHDAJ, OEPZ VGNISP SHLZEJWPO, MKOAFXQSHHQ CKAO QWVQHG IJEPZQMLEY, EZEYZ QK YGQUMPWLMDW. LLMJABGVM, EX BZA CIG HAFKBZ EK SFKSF (GN YYMKOAV), OQTXZSYPARO PDW KALDWV LATL NJKI MBKAHX, GBBKIB XU XPW GWC DAJYXP, SAPT LNGHCUA LLM LHSMV PAPX KQXLVIUPAV NJKI MBKAHX, SHOG WXBOWX TU LLM GAQ TWJCLL. EB EVQ HVWTWXDI OKNV AJ LLM LHSMV PAPX AO CRWOJ GV UWJ FM CQWWAWZ, MBK OWPN-OQTXZSYPASV YWF JW NWGWYJERIL, SZMKZ WDPWOO JIKGRAJC GB LLM GAQ JQ OMFBJWYLMVY PZI CJKOR HHWARBWTP JZGI LLM YEHLMJ PWBB. GWC WHEEMVSPEGR AO WWXWYESPTQ QKINMH SKIAJOL AZKNL UWOOSKMK. XSZ ATSQXDA MWQFC DMWF WK BZA CIG XADSE:";
      System.out.println(prob(s));
    }
}