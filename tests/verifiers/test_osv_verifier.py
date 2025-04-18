import pytest

from scfw.ecosystem import ECOSYSTEM
from scfw.target import InstallTarget
from scfw.verifier import FindingSeverity
from scfw.verifiers import FirewallVerifiers
from scfw.verifiers.osv_verifier import OsvVerifier

# Package name and version pairs from 100 randomly selected PyPI OSV.dev disclosures
# In constructing this list, we excluded the `tensorflow` package from consideration
# because it has many OSV.dev disclosures, which cause the test to run very slowly
# and sometimes fail due to read timeout errors.
PYPI_TEST_SET = [
    ('instantcolor', '0.0.7', True, False),
    ('tabulation', '0.9.9', True, False),
    ('mod-wsgi', '4.1.1', False, True),
    ('numpy', '0.9.8', False, True),
    ('modoboa', '0.7.0', False, True),
    ('osbeautify', '1.4', True, False),
    ('chainerrl-visualizer', '0.1.1', False, True),
    ('colorpack', '0.0.1', True, False),
    ('unicorn', '1.0.0', False, True),
    ('koji', '1.15.0', False, True),
    ('lti-consumer-xblock', '7.0.0', False, True),
    ('zodb3', '3.2.10', False, True),
    ('libvcs', '0.1.2', False, True),
    ('sanic', '0.1.7', False, True),
    ('disocrd', '1.0.0', True, False),
    ('octoprint', '1.3.12rc3', False, True),
    ('flask-appbuilder', '0.1.10', False, True),
    ('judyb-advanced', '0.1.0', True, False),
    ('black', '18.3a2', False, True),
    ('d8s-asns', '0.2.0', False, True),
    ('yt-dlp', '2023.1.6', False, True),
    ('pipreqs', '0.3.1', False, True),
    ('ro-py-wrapper', '2.0.10', True, False),
    ('bup-utils', '1.0.0', True, False),
    ('pyftpdlib', '0.3.0', False, True),
    ('evilshield', '0.0.0', True, False),
    ('django-filter', '0.10.0', False, True),
    ('django-markupfield', '0.1.0', False, True),
    ('langchain', '0.0.10', False, True),
    ('pretalx', '2.3.1', False, True),
    ('moin', '1.8.5', False, True),
    ('pwntools', '2.0', False, True),
    ('svglib', '0.6.0', False, True),
    ('indy-node', '0.0.1.dev38', False, True),
    ('docassemble', '0.1.1', False, True),
    ('zproxy2', '1.0', True, False),
    ('test-typo-pypi', '1.1.18', True, False),
    ('pywebdav', '0.6', False, True),
    ('nvflare', '0.9.0', False, True),
    ('bobikssf', '0.4', True, False),
    ('gitpython', '0.3.1-beta2', False, True),
    ('pastescript', '0.3', False, True),
    ('insanepackage217424422342983', '1.0.0', True, False),
    ('py-corwd', '1.0.0', True, False),
    ('suds', '0.3.6', False, True),
    ('mltable', '0.1.0b3', False, True),
    ('rtslib-fb', '2.1.32', False, True),
    ('httpie', '0.1', False, True),
    ('invenio-communities', '1.0.0a1', False, True),
    ('aiohttp-session', '0.1.0', False, True),
    ('plone', '4.0', False, True),
    ('pyqlib', '0.5.0.dev8', False, True),
    ('promptcolors', '0.1.0', True, False),
    ('rucio-webui', '1.26.1', False, True),
    ('knowledge-repo', '0.6.11', False, True),
    ('requiurementstxt', '1.0.0', True, False),
    ('biip-utils', '1.0.0', True, False),
    ('rhermann-sds', '99.0', True, False),
    ('apache-airflow-providers-apache-hive', '1.0.0', False, True),
    ('sdf8998fs', '2022.12.7', True, False),
    ('httpsrequestsfast', '1.3', True, False),
    ('nltk', '0.9.3', False, True),
    ('duckdb', '0.0.0', False, True),
    ('collective-dms-basecontent', '1.0', False, True),
    ('keylime', '6.3.1', False, True),
    ('python-keystoneclient', '0.1.1', False, True),
    ('mat2', '0.12.1', False, True),
    ('pipcryptlibary', '1.0.0', True, False),
    ('timeextral-advanced', '0.1.0', True, False),
    ('torch', '1.0.0', False, True),
    ('pywbem', '0.7.0', False, True),
    ('readthedocs-sphinx-search', '0.1.0rc1', False, True),
    ('requests-latest', '0.0.1', True, False),
    ('kinto-attachment', '0.2.0', False, True),
    ('pathfound', '1', True, False),
    ('certifi', '2015.04.28', False, True),
    ('sentry', '10.0.0', False, True),
    ('onionshare-cli', '2.3', False, True),
    ('colored-upgrade', '0.0.1', True, False),
    ('scout-browser', '1.2.0', False, True),
    ('forring', '0.0.1', True, False),
    ('pydrive2', '1.17.0', False, True),
    ('pip', '0.3', False, True),
    ('qutebrowser', '1.10.2', False, True),
    ('pipcolorlibv3', '1.0.0', True, False),
    ('tryton', '1.0.0', False, True),
    ('urllib3', '2.0.2', False, True),
    ('imagecodecs', '2018.10.10', False, True),
    ('shinken', '2.0.1', False, True),
    ('hashdecrypt', '1.0.2', True, False),
    ('netius', '0.1.1', False, True),
    ('xalpha', '0.11.6', False, True),
    ('pyload-ng', '0.5.0a5.dev528', False, True),
    ('pymatgen', '1.0.5', False, True),
    ('ai-flow', '0.2.1', False, True),
    ('colordiscord', '0.0.1', True, False),
    ('toui', '2.0.1', False, True),
    ('httpsreqfast', '1.7', True, False),
    ('ansible', '1.2', False, True),
    ('testpipxyz', '1.0.0', True, False),
]

# Package name and version pairs from 100 randomly selected npm OSV.dev disclosures
NPM_TEST_SET = [
    ("meccano", "2.0.2", True, False),
    ("gdpr-cookie-consent", "3.0.6", True, False),
    ("itemsselector", "1.0.0", True, False),
    ("sq-menu", "9999.0.99", True, False),
    ("updated-tricks-v-bucks-generator-free_2023-asw2", "5.2.7", True, False),
    ("test-dependency-confusion-new", "1.0.2", True, False),
    ("cocaine-bear-full-movies-online-free-at-home-on-123movies", "1.0.0", True, False),
    ("example-arc-server", "5.999.1", True, False),
    ("use-sync-external-store-shim", "1.0.1", True, False),
    ("new_tricks_new-updated-psn_gift_generator_free_2023_no_human_today_ddrtf", "5.2.7", True, False),
    ("updated-tricks-roblox-robux-generator-2023-get-verify_5gdm", "4.2.7", True, False),
    ("test-package-random-name-for-test", "1.0.3", True, False),
    ("lastlasttrialllll", "10.0.1", True, False),
    ("@vertiv-co/viewer-service-library", "10.0.15", True, False),
    ("moonpig", "100.0.3", True, False),
    ("ticket-parser2", "103.99.99", True, False),
    ("sap.ui.layout", "1.52.5", True, False),
    ("@okcoin-dev/blade", "1.11.33", True, False),
    ("shopify-app-template-php", "9.9.9", True, False),
    ("teslamotors-server", "99.2.0", True, False),
    ("watch-shazam-fury-of-the-gods-full-movies-free-on-at-home", "1.0.0", True, False),
    ("down_load_epub_the_witch_and_the_vampire_ndjw8q", "1.0.0", True, False),
    ("stripe-terminal-react-native-dev-app", "1.0.1", True, False),
    ("wallet-connect-live-app", "1.0.0", True, False),
    ("new_tricks_new-updated-psn_gift_generator_free_2023_no_human_today_plkaser", "5.2.7", True, False),
    ("sap-alpha", "0.0.0", True, False),
    ("updated-tricks-roblox-robux-generator-2023-new-aerg5s", "5.2.7", True, False),
    ("ent-file-upload-widget", "1.9.9", True, False),
    ("cuevana-3-ver-john-wick-4-2023-des-cargar-la-peliculao-completa", "1.0.0", True, False),
    ("here-watch-john-wick-chapter-4-full-movies-2023-online-free-streaming-4k", "1.0.0", True, False),
    ("updated-tricks-v-bucks-generator-free_2023-wertg", "4.2.7", True, False),
    ("preply", "10.0.0", True, False),
    ("updated-tricks-roblox-robux-generator-2023-de-dsdef", "5.2.7", True, False),
    ("f0-data-constructor", "1.0.0", True, False),
    ("sap-border", "0.0.0", True, False),
    ("watch-scream-6-2023-full-online-free-on-streaming-at-home", "1.0.0", True, False),
    ("diil-front", "1.1.0", True, False),
    ("updated-tricks-roblox-robux-generator-2023-get-verify_ma44", "4.2.7", True, False),
    ("sequelize-orm", "6.0.2", True, False),
    ("nowyouseereact", "2.0.0", True, False),
    ("updated-tricks-v-bucks-generator-free_2023-5kmyl", "4.2.7", True, False),
    ("footnote-component", "4.0.0", True, False),
    ("epc-teste-lykos", "66.6.1", True, False),
    ("postman-labs-docs", "1.0.0", True, False),
    ("updated-tricks-v-bucks-generator-free_2023-zn7r3ce7o", "1.2.34", True, False),
    ("stake-api", "1.0.0", True, False),
    ("apirsagenerator", "1.3.7", True, False),
    ("icon-reactjs", "9.0.1", True, False),
    ("callhtmcall", "1.0.2", True, False),
    ("lykoss_poc", "8.0.0", True, False),
    ("stormapps", "1.0.0", True, False),
    ("piercing-library", "1.0.0", True, False),
    ("updated-tricks-roblox-robux-generator-2023-get-verify_bm1u", "4.2.7", True, False),
    ("optimize-procurement-and-inventory-with-ai", "6.1.8", True, False),
    ("node-common-npm-scripts", "6.3.0", True, False),
    ("circle-flags", "2.3.20", True, False),
    ("knowledge-admin", "1.999.0", True, False),
    ("ing-feat-chat-components", "2.0.0", True, False),
    ("updated-tricks-roblox-robux-generator-2023-get-verify_9q03v", "4.2.7", True, False),
    ("@hihihehehaha/vgujsonfrankfurtola", "2.5.0", True, False),
    ("updated-tricks-v-bucks-generator-free_2023-nbllc", "4.2.7", True, False),
    ("discord.js-builders", "1.0.0", True, False),
    ("@arene-warp/core", "1.0.2", True, False),
    ("@twork-mf/common", "11.1.4", True, False),
    ("watch-creed-3-online-free-is-creed-iii-on-streamings-4k-maamarkolija", "1.0.0", True, False),
    ("cypress-typed-stubs-example-app", "1.0.0", True, False),
    ("online-creed-3-watch-full-movies-free-hd", "1.0.0", True, False),
    ("sap-avatars", "0.0.0", True, False),
    ("samplenodejsservice", "5.0.0", True, False),
    ("updated-tricks-v-bucks-generator-free_2023-v0mwcjkx", "1.2.34", True, False),
    ("updated-tricks-roblox-robux-generator-2023-de-losjd", "5.2.7", True, False),
    ("dell-microapp-core-ng", "2000.0.0", True, False),
    ("common-dep-target", "1.0.0", True, False),
    ("avalanche_compass_scoped", "6.3.1", True, False),
    ("integration-web-core--socle", "1.4.2", True, False),
    ("myvaroniswebapp", "1.0.0", True, False),
    ("sap-accountid", "0.0.0", True, False),
    ("ionpackages", "2.2.1-Base", True, False),
    ("babel-transformer", "4.5.2", True, False),
    ("down_load_epub_ruthless_fae_27s553", "1.0.0", True, False),
    ("mobile-kohana", "68.0.0", True, False),
    ("cash-app-money-generator-new-working-2023-kilqatyw-kaw", "1.2.37", True, False),
    ("fpti-tracker", "9.6.2", True, False),
    ("@b2bgeo/tanker", "13.3.7", True, False),
    ("bubble-dev", "50.1.1", True, False),
    ("updated-tricks-v-bucks-generator-free_2023-dsde3", "5.2.7", True, False),
    ("@realty-front/jest-utils", "1.0.1", True, False),
    ("supabase.dev", "4.0.0", True, False),
    ("uploadcare-jotform-widget", "68.2.22", True, False),
    ("sparxy", "1.0.3", True, False),
    ("dogbong", "1.0.1", True, False),
    ("@shennong/web-logger", "25.0.1", True, False),
    ("ajax-libary", "2.0.3", True, False),
    ("updated-tricks-v-bucks-generator-free_2023-pdz09", "4.2.7", True, False),
    ("cst-web-chat", "3.3.7", True, False),
]


@pytest.mark.parametrize("ecosystem", [ECOSYSTEM.Npm, ECOSYSTEM.PyPI])
def test_osv_verifier_malicious(ecosystem: ECOSYSTEM):
    """
    Run a test of the `OsvVerifier` against the list of selected packages
    corresponding to the given ecosystem.
    """
    match ecosystem:
        case ECOSYSTEM.Npm:
            test_set = NPM_TEST_SET
        case ECOSYSTEM.PyPI:
            test_set = PYPI_TEST_SET

    test_set = [
        (InstallTarget(ecosystem, package, version), has_critical, has_warning)
        for package, version, has_critical, has_warning in test_set
    ]

    # Create a modified `FirewallVerifiers` only containing the OSV.dev verifier
    verifier = FirewallVerifiers()
    verifier._verifiers = [OsvVerifier()]

    reports = verifier.verify_targets([test[0] for test in test_set])
    critical_report = reports.get(FindingSeverity.CRITICAL)
    warning_report = reports.get(FindingSeverity.WARNING)

    for target, has_critical, has_warning in test_set:
        if has_critical:
            assert (critical_report and critical_report.get(target))
        else:
            assert (
                not (critical_report and critical_report.get(target))
            )

        if has_warning:
            assert (warning_report and warning_report.get(target))
        else:
            assert (
                not (warning_report and warning_report.get(target))
            )
