// See https://aka.ms/new-console-template for more information


var dlinkCLient = new SwitchClient.DLink("192.168.3.93", "trueadm", "{rb,thufkfrnbrf}");

var authTask = await dlinkCLient.Auth();

if (authTask) {
    Console.WriteLine("Good");
} else Console.WriteLine("Bad");
