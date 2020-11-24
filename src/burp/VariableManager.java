package burp;

public final class VariableManager {
    private static boolean isStart;
    private static boolean stopTimer;

    public static boolean getisStart(){
        return isStart;
    }

    public static void setisStart(boolean isStart){
        VariableManager.isStart = isStart;
    }

    public static boolean getstopTimer(){
        return stopTimer;
    }

    public static void setstopTimer(boolean stopTimer){
        VariableManager.stopTimer = stopTimer;
    }

}
