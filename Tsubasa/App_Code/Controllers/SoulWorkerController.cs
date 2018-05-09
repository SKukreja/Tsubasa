using hbehr.recaptcha;
using System.Configuration;
using System.Data.SqlClient;
using System.Threading.Tasks;
using System.Web.Mvc;
using System.Xml.Linq;
using Tsubasa.Models;

/// <summary>
/// Summary description for SoulWorkerController
/// </summary>
public class SoulWorkerController : Controller
{
    [AllowAnonymous]
    public ActionResult Apply()
    {
        return View();
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<ActionResult> Apply(SoulWorkerViewModel model)
    {
        if (ModelState.IsValid)
        {
            //Get Captcha Response
            string userResponse = Request["g-recaptcha-response"];

            /* Previous formatting for Discord markdown (wasn't in a code block) 
            
            string application = "__**Application**__\n\n**"+ Request["Q1"] + "**\n" + model.CharacterName +
            "\n\n**" + Request["Q2"] + "**\n" + model.Class +
            "\n\n**" + Request["Q3"] + "**\n" + model.Location +
            "\n\n**" + Request["Q4"] + "**\n" + model.Experience +
            "\n\n**" + Request["Q5"] + "**\n" + model.Preference +
            "\n\n**" + Request["Q6"] + "**\n" + model.Voice +
            "\n\n**" + Request["Q7"] + "**\n" + model.Playtime +
            "\n\n**" + Request["Q8"] + "**\n" + model.PlayerType +
            "\n\n**" + Request["Q9"] + "**\n" + model.PrevGuilds +
            "\n\n**" + Request["Q10"] + "**\n" + model.LookingFor +
            "\n\n**" + Request["Q11"] + "**\n" + model.PrevMMOs +
            "\n\n**" + Request["Q12"] + "**\n" + model.Contribute + "\n\n\n";
            */

            //Build String to send to Discord Webhook
            string application = "```ini\n[" + Request["Q1"] + "]\n" + model.CharacterName +
            "\n\n[" + Request["Q2"] + "]\n" + model.Class +
            "\n\n[" + Request["Q3"] + "]\n" + model.CharacterLevel +
            "\n\n[" + Request["Q4"] + "]\n" + model.Location +
            "\n\n[" + Request["Q5"] + "]\n" + model.Experience +
            "\n\n[" + Request["Q6"] + "]\n" + model.Preference +
            "\n\n[" + Request["Q7"] + "]\n" + model.Voice +
            "\n\n[" + Request["Q8"] + "]\n" + model.Playtime +
            "\n\n[" + Request["Q9"] + "]\n" + model.PlayerType +
            "\n\n[" + Request["Q10"] + "]\n" + model.PrevGuilds +
            "\n\n[" + Request["Q11"] + "]\n" + model.LookingFor +
            "\n\n[" + Request["Q12"] + "]\n" + model.PrevMMOs +
            "\n\n[" + Request["Q13"] + "]\n" + model.Contribute +
            "\n\n[" + Request["Q14"] + "]\n" + model.DiscordHandle +
            "\n\n[" + Request["Q15"] + "]\n" + model.TwitchHandle +
            "\n\n[" + Request["Q16"] + "]\n" + model.YouTubeHandle + "```\n";

            /*Build XML to put in Answers column, Q[n] are questions from 
            hidden inputs to store what the questions were at the time in DB */

            XElement xml = new XElement("Application", 
                new XElement("Answer", 
                    new XAttribute("Question", Request["Q2"]),
                    model.Class),
                new XElement("Answer",
                    new XAttribute("Question", Request["Q3"]),
                    model.CharacterLevel),
                new XElement("Answer",
                    new XAttribute("Question", Request["Q4"]),
                    model.Location),
                new XElement("Answer",
                    new XAttribute("Question", Request["Q5"]),
                    model.Experience),
                new XElement("Answer",
                    new XAttribute("Question", Request["Q6"]),
                    model.Preference),
                new XElement("Answer",
                    new XAttribute("Question", Request["Q7"]),
                    model.Voice),
                new XElement("Answer",
                    new XAttribute("Question", Request["Q8"]),
                    model.Playtime),
                new XElement("Answer",
                    new XAttribute("Question", Request["Q9"]),
                    model.PlayerType),
                new XElement("Answer",
                    new XAttribute("Question", Request["Q10"]),
                    model.PrevGuilds),
                new XElement("Answer",
                    new XAttribute("Question", Request["Q11"]),
                    model.LookingFor),
                new XElement("Answer",
                    new XAttribute("Question", Request["Q12"]),
                    model.PrevMMOs),
                new XElement("Answer",
                    new XAttribute("Question", Request["Q13"]),
                    model.Contribute),
            new XElement("Answer",
                    new XAttribute("Question", Request["Q14"]),
                    model.DiscordHandle),
            new XElement("Answer",
                    new XAttribute("Question", Request["Q15"]),
                    model.TwitchHandle),
            new XElement("Answer",
                    new XAttribute("Question", Request["Q16"]),
                    model.YouTubeHandle));

            //If Captcha is valid, proceed
            bool validCaptcha = ReCaptcha.ValidateCaptcha(userResponse);
            if (validCaptcha)
            {
                //Send string to Discord Webhook
                DiscordWebhook.Webhook hook = new DiscordWebhook.Webhook("https://discordapp.com/api/webhooks/436045068197953536/YrzV8IBv51P0YOpN5HOreei4-fU9crjsyofjo_0MGyCYbA6cTtHLzT8BcmxdPc8C9q2Q");
                await hook.Send(application, "Website Application", "https://tsubasa.kr/Images/logo.png");

                //DB connection
                var connection = ConfigurationManager.ConnectionStrings["TsubasaDB"];

                //Store application in database
                using (SqlConnection conn = new SqlConnection(connection.ConnectionString))
                {
                    using (SqlCommand command = new SqlCommand() { CommandType = System.Data.CommandType.StoredProcedure, CommandText = "Apply", Connection = conn })
                    {
                        conn.Open();
                        command.Parameters.AddWithValue("@CharacterName", model.CharacterName);
                        command.Parameters.AddWithValue("@Game", "SoulWorker");
                        command.Parameters.AddWithValue("@Answers", xml.ToString());
                        command.ExecuteNonQuery();
                    }
                }
                return RedirectToAction("Confirm", "SoulWorker");
            }
            else
            {
                return RedirectToAction("Apply", "SoulWorker");
            }
        }
        return View();
    }

    [AllowAnonymous]
    public ActionResult Confirm()
    {
        return View();
    }
}