from scfw.ecosystem import ECOSYSTEM
from scfw.firewall import verify_install_targets
from scfw.target import InstallTarget
from scfw.verifiers.osv_verifier import OsvVerifier

# Package name and version pairs from 100 randomly selected PyPI OSV.dev disclosures
PIP_TEST_SET = [
    ("django-markupfield", "1.1.0"),
    ("plone", "4.0.6"),
    ("tensorflow", "2.1.3"),
    ("apache-airflow", "2.5.2rc2"),
    ("flask", "0.7"),
    ("django", "1.6.1"),
    ("api-hypixel", "1.0.4"),
    ("trytond", "3.0.0"),
    ("cryptography", "38.0.0"),
    ("jupyter-server", "1.4.0"),
    ("gradio", "2.9b15"),
    ("tensorflow-cpu", "2.4.2"),
    ("ansible-runner", "2.1.0.0a1"),
    ("octoprint", "1.4.1rc2"),
    ("mocodo", "4.2.1"),
    ("getproxywebshare", "3.1.8"),
    ("waitress", "0.8.5"),
    ("pip-goodthing", "0.0.3"),
    ("plone-rest", "1.6.2"),
    ("rdiffweb", "2.4.11a1"),
    ("django-celery-results", "1.1.1"),
    ("apache-superset", "0.38.1"),
    ("spam", "4.0.2"),
    ("py-xml", "1.0"),
    ("urllitelib", "1.2.0"),
    ("djangorestframework", "2.3.7"),
    ("colomara", "1.0.0"),
    ("salt", "2014.7.0rc6"),
    ("hypedrop", "1.0.0"),
    ("scikit-learn", "0.9"),
    ("ansible", "1.2.2"),
    ("aiohttp", "3.6.1"),
    ("fedmsg", "0.5.0"),
    ("capmonstercloudclieet", "1.0.0"),
    ("democritus-file-system", "2021.1.27"),
    ("bottle", "0.10.5"),
    ("tensorflow-cpu", "2.4.0"),
    ("sclite", "1"),
    ("flask-admin", "1.0.4"),
    ("rdiffweb", "1.5.1b1"),
    ("tensorflow-gpu", "1.10.1"),
    ("py-cocd", "1.0.0"),
    ("ryu", "1.3"),
    ("tensorflow", "2.3.0"),
    ("pyjio", "1.0.1"),
    ("semurgdb", "0.1"),
    ("tensorflow", "1.7.0"),
    ("ansible", "2.2.0.0"),
    ("ajenti", "0.99.28"),
    ("apache-airflow", "2.2.1"),
    ("tensorflow-cpu", "2.3.0"),
    ("selenium", "2.20.0"),
    ("pysaml2", "4.1.0"),
    ("ait-core", "2.3.0"),
    ("hsbcgui", "0.0.8"),
    ("tensorflow", "1.10.0"),
    ("django", "2.2"),
    ("bleach", "0.3.4"),
    ("oauthenticator", "0.4.1"),
    ("salt", "0.13.0"),
    ("feedparser", "4.1"),
    ("kerberos", "1.1.1"),
    ("pip", "9.0.2"),
    ("tensorflow", "1.11.0"),
    ("salt", "2015.8.9"),
    ("torch", "1.12.0"),
    ("tensorflow", "2.8.2"),
    ("mercurial", "1.9.1"),
    ("tensorflow-gpu", "2.1.3"),
    ("tensorflow", "1.6.0"),
    ("jupyterlab", "0.20.4"),
    ("apache-airflow-providers-apache-hive", "2.1.0rc1"),
    ("tensorflow", "2.1.1"),
    ("django", "1.1.4"),
    ("web3toolzfor", "1.0"),
    ("tensorflow-gpu", "2.3.3"),
    ("90456984689490856", "0"),
    ("swift", "2.27.0"),
    ("django", "5.0.1"),
    ("vyper", "0.2.2"),
    ("figflix", "0.1"),
    ("azure-identity", "1.0.0b2"),
    ("proxieshexler", "1.0"),
    ("langchain", "0.0.259"),
    ("suds", "0.3.7"),
    ("paddlepaddle", "2.4.1"),
    ("tensorflow", "1.15.4"),
    ("python-bugzilla", "0.6.2"),
    ("py32obf", "0.1.6"),
    ("django", "5.0.3"),
    ("cobbler", "3.1.2"),
    ("pyfastcode", "1.0.0"),
    ("pastescript", "1.6.1"),
    ("mchypixel", "1.0.3"),
    ("testwhitesnake", "0.1"),
    ("rdiffweb", "1.4.1b3"),
    ("tensorflow", "2.0.4"),
    ("tensorflow", "1.15.5"),
    ("syssqlite2toolv2", "1.0.0"),
    ("zhpt1cscoe", "0.0.1"),
]

# Package name and version pairs from 100 randomly selected npm OSV.dev disclosures
NPM_TEST_SET = [
    ("meccano", "2.0.2"),
    ("gdpr-cookie-consent", "3.0.6"),
    ("itemsselector", "1.0.0"),
    ("sq-menu", "9999.0.99"),
    ("updated-tricks-v-bucks-generator-free_2023-asw2", "5.2.7"),
    ("test-dependency-confusion-new", "1.0.2"),
    ("cocaine-bear-full-movies-online-free-at-home-on-123movies", "1.0.0"),
    ("example-arc-server", "5.999.1"),
    ("use-sync-external-store-shim", "1.0.1"),
    ("new_tricks_new-updated-psn_gift_generator_free_2023_no_human_today_ddrtf", "5.2.7"),
    ("updated-tricks-roblox-robux-generator-2023-get-verify_5gdm", "4.2.7"),
    ("test-package-random-name-for-test", "1.0.3"),
    ("lastlasttrialllll", "10.0.1"),
    ("@vertiv-co/viewer-service-library", "10.0.15"),
    ("moonpig", "100.0.3"),
    ("ticket-parser2", "103.99.99"),
    ("sap.ui.layout", "1.52.5"),
    ("@okcoin-dev/blade", "1.11.33"),
    ("shopify-app-template-php", "9.9.9"),
    ("teslamotors-server", "99.2.0"),
    ("watch-shazam-fury-of-the-gods-full-movies-free-on-at-home", "1.0.0"),
    ("down_load_epub_the_witch_and_the_vampire_ndjw8q", "1.0.0"),
    ("stripe-terminal-react-native-dev-app", "1.0.1"),
    ("wallet-connect-live-app", "1.0.0"),
    ("new_tricks_new-updated-psn_gift_generator_free_2023_no_human_today_plkaser", "5.2.7"),
    ("sap-alpha", "0.0.0"),
    ("updated-tricks-roblox-robux-generator-2023-new-aerg5s", "5.2.7"),
    ("ent-file-upload-widget", "1.9.9"),
    ("cuevana-3-ver-john-wick-4-2023-des-cargar-la-peliculao-completa", "1.0.0"),
    ("here-watch-john-wick-chapter-4-full-movies-2023-online-free-streaming-4k", "1.0.0"),
    ("updated-tricks-v-bucks-generator-free_2023-wertg", "4.2.7"),
    ("preply", "10.0.0"),
    ("updated-tricks-roblox-robux-generator-2023-de-dsdef", "5.2.7"),
    ("f0-data-constructor", "1.0.0"),
    ("sap-border", "0.0.0"),
    ("watch-scream-6-2023-full-online-free-on-streaming-at-home", "1.0.0"),
    ("diil-front", "1.1.0"),
    ("updated-tricks-roblox-robux-generator-2023-get-verify_ma44", "4.2.7"),
    ("sequelize-orm", "6.0.2"),
    ("nowyouseereact", "2.0.0"),
    ("updated-tricks-v-bucks-generator-free_2023-5kmyl", "4.2.7"),
    ("footnote-component", "4.0.0"),
    ("epc-teste-lykos", "66.6.1"),
    ("postman-labs-docs", "1.0.0"),
    ("updated-tricks-v-bucks-generator-free_2023-zn7r3ce7o", "1.2.34"),
    ("stake-api", "1.0.0"),
    ("apirsagenerator", "1.3.7"),
    ("icon-reactjs", "9.0.1"),
    ("callhtmcall", "1.0.2"),
    ("lykoss_poc", "8.0.0"),
    ("stormapps", "1.0.0"),
    ("piercing-library", "1.0.0"),
    ("updated-tricks-roblox-robux-generator-2023-get-verify_bm1u", "4.2.7"),
    ("optimize-procurement-and-inventory-with-ai", "6.1.8"),
    ("node-common-npm-scripts", "6.3.0"),
    ("circle-flags", "2.3.20"),
    ("knowledge-admin", "1.999.0"),
    ("ing-feat-chat-components", "2.0.0"),
    ("updated-tricks-roblox-robux-generator-2023-get-verify_9q03v", "4.2.7"),
    ("@hihihehehaha/vgujsonfrankfurtola", "2.5.0"),
    ("updated-tricks-v-bucks-generator-free_2023-nbllc", "4.2.7"),
    ("discord.js-builders", "1.0.0"),
    ("@arene-warp/core", "1.0.2"),
    ("@twork-mf/common", "11.1.4"),
    ("watch-creed-3-online-free-is-creed-iii-on-streamings-4k-maamarkolija", "1.0.0"),
    ("cypress-typed-stubs-example-app", "1.0.0"),
    ("online-creed-3-watch-full-movies-free-hd", "1.0.0"),
    ("sap-avatars", "0.0.0"),
    ("samplenodejsservice", "5.0.0"),
    ("updated-tricks-v-bucks-generator-free_2023-v0mwcjkx", "1.2.34"),
    ("updated-tricks-roblox-robux-generator-2023-de-losjd", "5.2.7"),
    ("dell-microapp-core-ng", "2000.0.0"),
    ("common-dep-target", "1.0.0"),
    ("avalanche_compass_scoped", "6.3.1"),
    ("integration-web-core--socle", "1.4.2"),
    ("myvaroniswebapp", "1.0.0"),
    ("sap-accountid", "0.0.0"),
    ("ionpackages", "2.2.1-Base"),
    ("babel-transformer", "4.5.2"),
    ("down_load_epub_ruthless_fae_27s553", "1.0.0"),
    ("mobile-kohana", "68.0.0"),
    ("cash-app-money-generator-new-working-2023-kilqatyw-kaw", "1.2.37"),
    ("fpti-tracker", "9.6.2"),
    ("@b2bgeo/tanker", "13.3.7"),
    ("bubble-dev", "50.1.1"),
    ("updated-tricks-v-bucks-generator-free_2023-dsde3", "5.2.7"),
    ("@realty-front/jest-utils", "1.0.1"),
    ("supabase.dev", "4.0.0"),
    ("uploadcare-jotform-widget", "68.2.22"),
    ("sparxy", "1.0.3"),
    ("dogbong", "1.0.1"),
    ("@shennong/web-logger", "25.0.1"),
    ("ajax-libary", "2.0.3"),
    ("updated-tricks-v-bucks-generator-free_2023-pdz09", "4.2.7"),
    ("cst-web-chat", "3.3.7"),
]


def test_osv_verifier_malicious_pip():
    """
    Test that every vulnerable or malicious package in a random sample of OSV.dev
    PyPI publications of the given size (default OSV_SAMPLE_SIZE) has an `OsvVerifier`
    finding (and therefore would block).
    """
    _test_osv_verifier_malicious(ECOSYSTEM.PIP)


def test_osv_verifier_malicious_npm():
    """
    Test that every vulnerable or malicious package in a random sample of OSV.dev
    npm publications of the given size (default OSV_SAMPLE_SIZE) has an `OsvVerifier`
    finding (and therefore would block).
    """
    _test_osv_verifier_malicious(ECOSYSTEM.NPM)


def _test_osv_verifier_malicious(ecosystem: ECOSYSTEM):
    """
    Backend testing function for the `test_osv_verifier_malicious_*` tests.
    """
    match ecosystem:
        case ECOSYSTEM.PIP:
            test_set = PIP_TEST_SET
        case ECOSYSTEM.NPM:
            test_set = NPM_TEST_SET

    test_targets = list(map(lambda t: InstallTarget(ecosystem, t[0], t[1]), test_set))
    findings = verify_install_targets([OsvVerifier()], test_targets)
    assert findings
    for target in test_targets:
        assert target in findings
        assert findings[target]
