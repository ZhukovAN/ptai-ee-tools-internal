using MessagePack;
using Messages.DataContracts;
using Messages.DataContracts.Enums;
using Newtonsoft.Json;
using ptai.ee.tools.internals.description.generator.dto;
using Repository.Description;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace ptai.ee.tools.internals.description.generator
{
    class Program
    {
        static void Main(string[] args)
        {
            IEnumerable<IssueBaseMetadata> metadataList = GetAllMetadatas();
            Dictionary<string, IssueBaseMetadata> metadataDict = new Dictionary<string, IssueBaseMetadata>();
            foreach (IssueBaseMetadata item in metadataList) metadataDict.Add(item.Key, item);

            IReadOnlyCollection<PmPattern> patternList = GetAllPmPatterns();
            Dictionary<string, ProgrammingLanguages> patternDict = new Dictionary<string, ProgrammingLanguages>();
            foreach (PmPattern item in patternList) patternDict.Add(item.Key, item.ProgrammingLanguages);

            List<PtaiIssueDescription> descriptions = new List<PtaiIssueDescription>();

            IReadOnlyCollection<IssueDescriptionBase> desc = GetAllDescriptions();
            foreach (IssueDescriptionBase issueDescriptionBase in desc)
            {
                // Skip FP issues
                if (IssueType.Fingerprint == issueDescriptionBase.IssueType) continue;

                IssueBaseMetadata metadata = metadataDict.ContainsKey(issueDescriptionBase.Key) ? metadataDict[issueDescriptionBase.Key] : null;

                PtaiIssueDescription description = new PtaiIssueDescription();
                description.identity = issueDescriptionBase.Key;
                description.type = IssueType.BlackBox == issueDescriptionBase.IssueType
                    ? PtaiIssueDescription.IssueType.BLACKBOX
                    : IssueType.Configuration == issueDescriptionBase.IssueType
                    ? PtaiIssueDescription.IssueType.CONFIGURATION
                    : IssueType.Fingerprint == issueDescriptionBase.IssueType
                    ? PtaiIssueDescription.IssueType.SCA
                    : IssueType.Unknown == issueDescriptionBase.IssueType
                    ? PtaiIssueDescription.IssueType.UNKNOWN
                    : IssueType.Vulnerability == issueDescriptionBase.IssueType
                    ? PtaiIssueDescription.IssueType.VULNERABILITY
                    : IssueType.Weakness == issueDescriptionBase.IssueType
                    ? PtaiIssueDescription.IssueType.WEAKNESS
                    : PtaiIssueDescription.IssueType.YARAMATCH;
                if (null != metadata)
                {
                    description.level = IssueLevel.High == metadata.Level
                        ? PtaiIssueDescription.Level.HIGH
                        : IssueLevel.Medium == metadata.Level
                        ? PtaiIssueDescription.Level.MEDIUM
                        : IssueLevel.Low == metadata.Level
                        ? PtaiIssueDescription.Level.LOW
                        : IssueLevel.Potential == metadata.Level
                        ? PtaiIssueDescription.Level.POTENTIAL
                        : PtaiIssueDescription.Level.NONE;
                    if (metadata is IssueMetadata issueMetadata)
                    {
                        List<string> nist = String.IsNullOrEmpty(issueMetadata.Nist) ? null : Regex.Matches(issueMetadata.Nist, @"[0-9a-zA-Z\.\-]+").Cast<Match>().Select(match => match.Value).ToList();
                        List<string> owasp = String.IsNullOrEmpty(issueMetadata.OwaspId) ? null : Regex.Matches(issueMetadata.OwaspId, @"[0-9a-zA-Z\.\-]+").Cast<Match>().Select(match => match.Value).ToList();
                        List<string> pciDss = String.IsNullOrEmpty(issueMetadata.PciId) ? null : Regex.Matches(issueMetadata.PciId, @"[0-9a-zA-Z\.\-]+").Cast<Match>().Select(match => match.Value).ToList();
                        List<string> cwe = String.IsNullOrEmpty(issueMetadata.CweId) ? null : Regex.Matches(issueMetadata.CweId, @"[0-9a-zA-Z\.\-]+").Cast<Match>().Select(match => match.Value).ToList();
                        if ((nist?.Any() ?? false) || (owasp?.Any() ?? false) || (pciDss?.Any() ?? false) || (cwe?.Any() ?? false))
                        {
                            description.categories = new Dictionary<PtaiIssueDescription.Category, List<string>>();
                            if ((nist?.Any() ?? false)) description.categories[PtaiIssueDescription.Category.NIST] = nist;
                            if ((owasp?.Any() ?? false)) description.categories[PtaiIssueDescription.Category.OWASP] = owasp;
                            if ((pciDss?.Any() ?? false)) description.categories[PtaiIssueDescription.Category.PCIDSS] = pciDss;
                            if ((cwe?.Any() ?? false)) description.categories[PtaiIssueDescription.Category.CWE] = cwe;
                        }
                    }
                }

                if (patternDict.ContainsKey(issueDescriptionBase.Key))
                {
                    uint languages = (uint)patternDict[issueDescriptionBase.Key];
                    HashSet<PtaiIssueDescription.Language> languagesSet = new HashSet<PtaiIssueDescription.Language>();
                    foreach (ProgrammingLanguages language in Enum.GetValues(typeof(ProgrammingLanguages)))
                    {
                        if (0 == (languages & (int)language)) continue;
                        if (ProgrammingLanguages.Php == language)
                            languagesSet.Add(PtaiIssueDescription.Language.PHP);
                        else if (ProgrammingLanguages.Java == language)
                            languagesSet.Add(PtaiIssueDescription.Language.JAVA);
                        else if (ProgrammingLanguages.CSharp == language)
                            languagesSet.Add(PtaiIssueDescription.Language.CSHARP);
                        else if (ProgrammingLanguages.VB == language)
                            languagesSet.Add(PtaiIssueDescription.Language.VB);
                        else if (ProgrammingLanguages.JavaScript == language)
                            languagesSet.Add(PtaiIssueDescription.Language.JS);
                        else if (ProgrammingLanguages.Python == language)
                            languagesSet.Add(PtaiIssueDescription.Language.PYTHON);
                        else if (ProgrammingLanguages.ObjectiveC == language)
                            languagesSet.Add(PtaiIssueDescription.Language.OBJECTIVEC);
                        else if (ProgrammingLanguages.Swift == language)
                            languagesSet.Add(PtaiIssueDescription.Language.SWIFT);
                        else if (ProgrammingLanguages.Kotlin == language)
                            languagesSet.Add(PtaiIssueDescription.Language.KOTLIN);
                        else if (ProgrammingLanguages.Go == language)
                            languagesSet.Add(PtaiIssueDescription.Language.GO);
                        else if (ProgrammingLanguages.TSql == language)
                            languagesSet.Add(PtaiIssueDescription.Language.SQL);
                        else if (ProgrammingLanguages.MySql == language)
                            languagesSet.Add(PtaiIssueDescription.Language.SQL);
                        else if (ProgrammingLanguages.PlSql == language)
                            languagesSet.Add(PtaiIssueDescription.Language.SQL);
                        else if (ProgrammingLanguages.C == language)
                            languagesSet.Add(PtaiIssueDescription.Language.CPP);
                        else if (ProgrammingLanguages.CPlusPlus == language)
                            languagesSet.Add(PtaiIssueDescription.Language.CPP);
                    }
                    if (languagesSet.Any()) description.languages = languagesSet;
                }

                foreach (PtaiIssueDescription.Locale locale in Enum.GetValues(typeof(PtaiIssueDescription.Locale)))
                {
                    DescriptionBaseValue baseValue = issueDescriptionBase[(int)locale];
                    PtaiIssueDescription.I18n value = new PtaiIssueDescription.I18n();
                    value.header = baseValue.Header;
                    value.description = baseValue.Description;
                    if (baseValue is DescriptionValue descriptionValue && !String.IsNullOrEmpty(descriptionValue.Html))
                    {
                        // Create byte-array representation of UTF8-encoded string
                        byte[] buffer = System.Text.Encoding.Unicode.GetBytes(descriptionValue.Html);
                        // Zip string to memory stream
                        MemoryStream memoryStream = new MemoryStream();
                        using (GZipStream zip = new GZipStream(memoryStream, CompressionMode.Compress, true))
                        {
                            zip.Write(buffer, 0, buffer.Length);
                        }

                        memoryStream.Position = 0;
                        MemoryStream outStream = new MemoryStream();

                        byte[] compressed = new byte[memoryStream.Length];
                        memoryStream.Read(compressed, 0, compressed.Length);

                        byte[] gzBuffer = new byte[compressed.Length + 4];
                        System.Buffer.BlockCopy(compressed, 0, gzBuffer, 4, compressed.Length);
                        System.Buffer.BlockCopy(BitConverter.GetBytes(buffer.Length), 0, gzBuffer, 0, 4);
                        string base64 = Convert.ToBase64String(gzBuffer);

                        value.html = new PtaiIssueDescription.Html();
                        if (base64.Length < descriptionValue.Html.Length)
                        {
                            value.html.data = base64;
                            value.html.zipped = true;
                            Console.WriteLine($"HTML pack ratio {base64.Length / descriptionValue.Html.Length}");
                        }
                        else
                            value.html.data = descriptionValue.Html;
                    }

                    description.values.Add(locale, value);
                }
                if (0 == description.values.Count)
                {
                    Console.Error.WriteLine($"No values for {description.identity}");
                    continue;
                }
                descriptions.Add(description);
                Console.WriteLine($"Description {description.identity} added");
            }

            string str = JsonConvert.SerializeObject(descriptions);
            File.WriteAllText(@"descriptions.json", str, System.Text.Encoding.UTF8);
        }

        public static IReadOnlyCollection<IssueBaseMetadata> GetAllMetadatas()
        {
            Assembly assembly = typeof(DescriptionService).Assembly;
            using (Stream manifestResourceStream1 = assembly.GetManifestResourceStream("Repository.Description.Resources.Issue.Metadatas"))
            {
                return LZ4MessagePackSerializer.Deserialize<IReadOnlyCollection<IssueBaseMetadata>>(manifestResourceStream1, false);
            }
        }

        public static IReadOnlyCollection<PmPattern> GetAllPmPatterns()
        {
            using (Stream manifestResourceStream = typeof(DescriptionService).Assembly.GetManifestResourceStream("Repository.Description.Resources.Patterns"))
                return LZ4MessagePackSerializer.Deserialize<IReadOnlyCollection<PmPattern>>(manifestResourceStream, false);
        }

        public static IReadOnlyCollection<IssueDescriptionBase> GetAllDescriptions()
        {
            Assembly assembly = typeof(DescriptionService).Assembly;
            using (Stream manifestResourceStream1 = assembly.GetManifestResourceStream("Repository.Description.Resources.Issue.Descriptions"))
            {
                using (Stream manifestResourceStream2 = assembly.GetManifestResourceStream("Repository.Description.Resources.Issue.Fingerprint.Descriptions"))
                    return (IReadOnlyCollection<IssueDescriptionBase>)LZ4MessagePackSerializer.Deserialize<IReadOnlyCollection<IssueDescriptionBase>>(manifestResourceStream1, false).Union<IssueDescriptionBase>((IEnumerable<IssueDescriptionBase>)LZ4MessagePackSerializer.Deserialize<IReadOnlyCollection<IssueDescriptionBase>>(manifestResourceStream2, false)).ToArray<IssueDescriptionBase>();
            }
        }
    }
}
