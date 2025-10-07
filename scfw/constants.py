"""
Provides various configuration-related constants.
"""

DD_SOURCE = "scfw"
"""
Source value for Datadog logging.
"""

DD_SERVICE = "scfw"
"""
Service value for Datadog logging.
"""

DD_ENV = "dev"
"""
Default environment value for Datadog logging.
"""

DD_API_KEY_VAR = "DD_API_KEY"
"""
The environment variable under which the firewall looks for a Datadog API key.
"""

DD_LOG_LEVEL_VAR = "SCFW_DD_LOG_LEVEL"
"""
The environment variable under which the firewall looks for a Datadog log level setting.
"""

DD_AGENT_PORT_VAR = "SCFW_DD_AGENT_LOG_PORT"
"""
The environment variable under which the firewall looks for a port number on which to
forward firewall logs to the local Datadog Agent.
"""

ON_WARNING_VAR = "SCFW_ON_WARNING"
"""
The environment variable under which the firewall looks for the user's choice of
`FirewallAction` to take for commands with only warning-level findings.
"""

SCFW_HOME_VAR = "SCFW_HOME"
"""
The environment variable under which the firewall looks for its home (cache) directory.
"""
