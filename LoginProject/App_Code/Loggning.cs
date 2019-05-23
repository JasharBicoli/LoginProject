using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Serilog;

namespace LoginProject.App_Code
{
    public class Loggning
    {
        public static void AppInitialize()
        {
            // Skapa en Logger-singleton.
            // Ordet "singleton" betyder att man har ETT objekt som finns tillgängligt globalt
            // När man har en singleton (t.ex. en logger) så får övrig kod INTE skapa egna objekt av denna typ
            // utan alla måste använda ett och samma objekt. 
            // Denna singleton skapas när programmet startas och finns kvar ända tills programmet avslutas.
            // På så vis ser vi till att det inte blir några skrivfel som skulle kunna uppkomma
            // om en massa olika objekt försökte skriva samtidigt till samma fil.
            var filePath = @"C:\logs\WcfLog-.txt";
            // Not: @-symbolen gör att strängen tolkas bokstavligt. Tecknet \ är då inte ett escape-tecken.
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .WriteTo.File(filePath, rollingInterval: RollingInterval.Day)
                .CreateLogger();
            // Här försöker vi skriva till logfilen med lite olika log-nivåer
            // Verbose är lägsta möjliga nivå, men eftersom vi satte
            // .MinimumLevel.Debug() här ovan så ignoreras alla Log.Verbose()
            // Dessa kommandon kan du nu köra precis var du vill. 
            // Glöm bara inte att lägga in using Serilog på de sidor där du kör kommandona
            Log.Verbose("Demo - Verbose");
            Log.Debug("Demo - Debug");
            Log.Information("Demo - Information");
            Log.Warning("Demo - Warning");
            Log.Error("Demo - Error");
            Log.Fatal("Demo - Fatal");
        }
    }
}