using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ptai.ee.tools.internals.description.generator.dto
{
    [JsonObject(ItemNullValueHandling = NullValueHandling.Ignore)]
    public class PtaiIssueDescription
    {
        public string identity { get; set; }


        [JsonConverter(typeof(StringEnumConverter))]
        public enum IssueType
        {
            VULNERABILITY, WEAKNESS, SCA, CONFIGURATION, BLACKBOX, YARAMATCH, UNKNOWN
        }


        [JsonConverter(typeof(StringEnumConverter))]
        public IssueType type { get; set; }

        public enum Level
        {
            NONE, POTENTIAL, LOW, MEDIUM, HIGH
        }

        public enum Category { CWE, NIST, OWASP, PCIDSS };

        public Dictionary<Category, List<string>> categories { get; set; }

        [JsonConverter(typeof(StringEnumConverter))]
        public enum Language
        {
            PHP, JAVA, CSHARP, VB, JS, GO, CPP, PYTHON, SQL, OBJECTIVEC, SWIFT, KOTLIN
        }

        public HashSet<Language> languages { get; set; }

        [JsonConverter(typeof(StringEnumConverter))]
        public Level level { get; set; }

        public enum Locale : int
        {
            EN = 1033,
            RU = 1049
        }

        public Dictionary<Locale, I18n> values { get; } = new Dictionary<Locale, I18n>();

        [JsonObject(ItemNullValueHandling = NullValueHandling.Ignore)]
        public class I18n
        {
            public string header { get; set; }
            public string description { get; set; }
            public Html html { get; set; }
        }

        public class Html
        {
            public Boolean zipped { get; set; } = false;
            public string data { get; set; } = null;
        }
    }
}
