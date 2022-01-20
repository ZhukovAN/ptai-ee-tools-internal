package com.ptsecurity.appsec.ai.ee.utils.internal.description.generator.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;
import java.util.Map;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class IssueDescription {
    @JsonProperty("identity")
    protected String identity;

    @JsonProperty("type")
    protected BaseIssue.Type type;

    public enum Category {
        CWE, OWASP, PCIDSS, NIST
    }

    protected Set<ScanBrief.ScanSettings.Language> languages;

    protected Map<Category, List<String>> categories;

    @JsonProperty("level")
    protected BaseIssue.Level level;

    @Getter
    @Setter
    @NoArgsConstructor
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Value {
        @JsonProperty("header")
        protected String header;

        @JsonProperty("description")
        protected String description;

        @Getter
        @Setter
        @NoArgsConstructor
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public static class Html {
            protected boolean zipped;
            protected String data;
        }

        @JsonProperty("html")
        protected Html html;
    }

    @JsonProperty("values")
    protected Map<Reports.Locale, Value> values;
}
