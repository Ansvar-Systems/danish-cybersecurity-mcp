/**
 * Seed the CFCS (Center for Cybersikkerhed) database with sample guidance,
 * advisories, and frameworks for testing.
 *
 * Usage:
 *   npx tsx scripts/seed-sample.ts
 *   npx tsx scripts/seed-sample.ts --force
 */

import Database from "better-sqlite3";
import { existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

const DB_PATH = process.env["CFCS_DB_PATH"] ?? "data/cfcs.db";
const force = process.argv.includes("--force");

const dir = dirname(DB_PATH);
if (!existsSync(dir)) { mkdirSync(dir, { recursive: true }); }
if (force && existsSync(DB_PATH)) { unlinkSync(DB_PATH); console.log(`Deleted existing database at ${DB_PATH}`); }

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(SCHEMA_SQL);
console.log(`Database initialised at ${DB_PATH}`);

interface FrameworkRow { id: string; name: string; name_en: string; description: string; document_count: number; }

const frameworks: FrameworkRow[] = [
  { id: "cfcs-vejledning", name: "CFCS Vejledninger", name_en: "CFCS Guidance Publications",
    description: "Vejledninger og anbefalinger fra Center for Cybersikkerhed (CFCS) inden for netvaerkssikkerhed, cybertrusler, incidenthindring og kritisk infrastruktur beskyttelse.",
    document_count: 5 },
  { id: "nis2-dk", name: "NIS2 i Danmark", name_en: "NIS2 Directive Implementation in Denmark",
    description: "CFCS er national CSIRT og Erhvervsstyrelsen er koordinerende kompetent myndighed for NIS2-direktivet i Danmark. Vejledning for virksomheder der er omfattet af NIS2.",
    document_count: 2 },
  { id: "critisk-infrastruktur", name: "Kritisk Infrastruktur Beskyttelse", name_en: "Critical Infrastructure Protection",
    description: "CFCS vejledning for operatorer af kritisk infrastruktur i Danmark inden for energi, vand, transport og digital infrastruktur.",
    document_count: 2 },
];

const insertFramework = db.prepare("INSERT OR IGNORE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, ?)");
for (const f of frameworks) { insertFramework.run(f.id, f.name, f.name_en, f.description, f.document_count); }
console.log(`Inserted ${frameworks.length} frameworks`);

interface GuidanceRow { reference: string; title: string; title_en: string; date: string; type: string; series: string; summary: string; full_text: string; topics: string; status: string; }

const guidance: GuidanceRow[] = [
  {
    reference: "CFCS-2023-001", title: "Ransomware — vejledning til organisationer",
    title_en: "Ransomware — Guidance for Organisations", date: "2023-04-15",
    type: "guidance", series: "CFCS",
    summary: "CFCS vejledning om ransomware-trusler, forebyggende foranstaltninger og haendelsesrespons for danske organisationer. Daekker backup-strategier, netvaerkssegmentering og handlinger ved angreb.",
    full_text: "Ransomware er en af de storste cybertrusler mod danske organisationer. Forebyggelse: Organisationer bor opretholde regelmaessige og testede offline sikkerhedskopier. Systemer skal patches rettidigt. Multifaktorgodkendelse skal implementeres pa alle systemer. Netvaerkssegmentering begraenser lateral bevaegelse ved angreb. Medarbejdertrae ning er afgorende — de fleste ransomwareangreb starter med phishing. Detektion: Anven d EDR-vaerktoj (Endpoint Detection and Response) og centraliseret logning. Uregelmessig krypteringsaktivitet og udsaedvanlig netvaerkstrafik til eksterne IP-adresser er indikatorer pa kompromittering. Respons: Hvis ransomware opdages, skal berorte systemer isoleres umiddelbart. Betal ikke losen — det garanterer ikke datagendannelse og finansierer kriminel aktivitet. Anmeld til CFCS og politiet. Bevar retsmedicinsk bevis for udbedring. Genopretning: Gendan fra rene sikkerhedskopier. Verificer sikkerhedskopiers integritet for gendannelse. Implementer laerdommene for at forhindre gentagelse. NIS2-forpligtelser: Virksomheder omfattet af NIS2 skal anmelde betydelige haendelser til CFCS inden for 24 timer.",
    topics: JSON.stringify(["ransomware", "haendelsesrespons", "backup", "NIS2"]), status: "current",
  },
  {
    reference: "CFCS-2023-002", title: "NIS2 i Danmark — vejledning for daekkede virksomheder",
    title_en: "NIS2 in Denmark — Guidance for Covered Organisations", date: "2023-10-01",
    type: "standard", series: "NIS2-DK",
    summary: "CFCS vejledning for virksomheder der er klassificeret som essentielle eller vigtige enheder under NIS2-direktivet som implementeret i dansk ret. Daekker registrering, sikkerhedsforanstaltninger, haendelsesrapportering og leverandorkaedekrav.",
    full_text: "NIS2-direktivet (Direktiv (EU) 2022/2555) blev implementeret i dansk ret i 2024. CFCS er national CSIRT, og Erhvervsstyrelsen er koordinerende kompetent myndighed. Essentielle enheder i Danmark inbefattar energi, transport, bank, finansmarkedsinfrastruktur, sundhed, drikkevand, spildevand, digital infrastruktur, IKT-tjenesteforvaltning, offentlig forvaltning og rumfart. Vigtige enheder inbefattar post- og kurertjenester, affaldshaandtering, kemikalier, fodevarer, fremstilling og digitale udbydere. Sikkerhedsforanstaltninger: Alle daekkede enheder skal implementere foranstaltninger vedr. risikoanalyse, haendelseshaandtering, forretningskontinuitet inkl. sikkerhedskopiering, leverandorkaede sikkerhed, netvaerk og systemsikkerhed, kryptografi, personalets sikkerhed, adgangskontrol og multifaktorgodkendelse. Haendelsesrapportering: Betydelige haendelser skal anmeldes til CFCS inden 24 timer (tidlig advarsel), 72 timer (haendelsesanmeldelse) og 30 dage (slutrapport). Sanktioner: Kompetente myndigheder kan palagge administrative boer op til 10.000.000 EUR eller 2 % af den arlige verdensomspaendende omsaetning for essentielle enheder.",
    topics: JSON.stringify(["NIS2", "CFCS", "compliance", "haendelsesrapportering"]), status: "current",
  },
  {
    reference: "CFCS-2023-003", title: "Cybertruslen mod Danmark 2023",
    title_en: "The Cyber Threat against Denmark 2023", date: "2023-11-20",
    type: "recommendation", series: "CFCS",
    summary: "CFCS arlige vurdering af cybertrusselsbilledet mod Danmark. Daekker trusler fra statsstottede aktorer, cyberkriminalitet, og hacktivisme med fokus pa kritisk infrastruktur og offentlige myndigheder.",
    full_text: "CFCS vurderer, at truslen fra cyberspionage mod Danmark er meget hoj. Statsstottede aktorer fra Rusland, Kina, Iran og Nordkorea er de primeare trusselsstorer. Russisk cyberspionage: Russiske statsstottede aktorer forsotter med at spionere mod dansk kritisk infrastruktur, forsvar, og politiske institutioner. APT29 (Cozy Bear) og Sandworm er de mest aktive grupper mod danske mal. Kinesisk cyberspionage: Kinesiske aktorer som APT40 og APT31 er aktive mod danske virksomheder med avanceret teknologi og forsvarsindustri. Cyberkriminalitet: Ransomwaregrupper som LockBit, ALPHV/BlackCat og Cl0p er de storste trusler mod danske virksomheder. Angrebene er profitmotiverede og rammer pa tvaers af sektorer. Hacktivisme: Pro-russiske hacktivistegrupper som KillNet og NoName057(16) har gjennomfort DDoS-angreb mod danske offentlige websites og kritisk infrastruktur som reaktion pa dansk NATO-stotte. Anbefalinger: CFCS anbefaler, at alle organisationer implementerer grundlaeggende sikkerhedsforanstaltninger: MFA, patchning, sikkerhedskopiering og netvaerkssegmentering.",
    topics: JSON.stringify(["trusselvurdering", "cyberspionage", "ransomware", "kritisk-infrastruktur"]), status: "current",
  },
  {
    reference: "CFCS-2024-001", title: "Leverandorkaede sikkerhed — vejledning",
    title_en: "Supply Chain Security — Guidance", date: "2024-01-20",
    type: "guidance", series: "CFCS",
    summary: "CFCS vejledning om haandtering af cybersikkerhedsrisici i leverandorkaden for danske organisationer. Inkluderer risikovurdering af IKT-leverandorer, aftalekrav og tredjeparts overvagning, tilpasset NIS2 leverandorkadeforpligtelser.",
    full_text: "Leverandorkaede angreb er steget markant. Risikovurdering: Kategoriser leverandorer efter kritikalitet for jeres drift. For kritiske IKT-leverandorer, udfore due diligence inkl. sikkerhedsfregeblanket, revisioner og gennemgang af certificeringer (ISO 27001, SOC 2). Aftalekrav: Inkluder cybersikkerhedskrav i leverandorkontrakter: revisionsret, forpligtelse til at anmelde haendelser i overensstemmelse med NIS2-rapporteringstidslinje, minimumssikkerhedsstandarder, krav til datahaandtering og adgangskontroller samt krav om ansvarlig offentliggorelse af sarbarheder. Overvagning: Overva g kritiske leverandorer lobende. Gennemga leverandorers sikkerhedspostning arligt. SBOM: For programvareleverandorer, anmod om Software Bill of Materials (SBOM) for at forsta komponentafhangigheder. NIS2-krav: Artikel 21 i NIS2-direktivet kraever, at essentielle og vigtige enheder adresserer leverandorkaede sikkerhed.",
    topics: JSON.stringify(["leverandorkaede", "tredjepart", "NIS2", "IKT-leverandorer"]), status: "current",
  },
  {
    reference: "CFCS-2024-002", title: "Sikkerhed i industrielle styresystemer og OT-miljoer",
    title_en: "Security in Industrial Control Systems and OT Environments", date: "2024-04-10",
    type: "guidance", series: "CFCS",
    summary: "CFCS vejledning om cybersikkerhed i industrielle styresystemer (ICS) og OT-miljoer for danske operatorer af kritisk infrastruktur. Daekker risikoanalyse, netvaerkssegmentering, fjernadgang og haendelsesrespons.",
    full_text: "Industrielle styresystemer (ICS) og OT-miljoer i kritisk infrastruktur star over for eskalerende cybertrusler. Risikoanalyse: Udfore en OT-specifik risikoanalyse. Identificer alle ICS-komponenter (PLC, SCADA, DCS, HMI). Dokumenter kommunikationsveje mellem IT og OT. Netvaerkssegmentering: Implementer klar adskillelse mellem IT-netvaerk og OT-netvaerk. Brug demilitariserede zoner (DMZ) for systemer der skal kommunikere med bade IT og OT. Fjernadgang: Al fjernadgang til OT-miljoer skal vaere dokumenteret og godkendt. Brug dedikerede jump-servere for OT-adgang. Kraev MFA for alle fjernadgange. Overvagning: Implementer OT-specifike IDS-losninger. Fastlaeg en baseline for normalt OT-netvaerksadfaerd. Haendelsesrespons: OT-haendelsesplaner skal tage hojde for sikkerhed (menneskelig sikkerhed) og fysisk indvirkning pa processer. Planerne skal testes med tabletop-ovelser. Patching: OT-systemer kan sjaeldent patches umiddelbart. Implementer kompenserende kontroller der maling ikke er mulig.",
    topics: JSON.stringify(["OT", "ICS", "SCADA", "kritisk-infrastruktur", "netvaerkssegmentering"]), status: "current",
  },
];

const insertGuidance = db.prepare("INSERT OR IGNORE INTO guidance (reference, title, title_en, date, type, series, summary, full_text, topics, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
const insertGuidanceAll = db.transaction(() => { for (const g of guidance) { insertGuidance.run(g.reference, g.title, g.title_en, g.date, g.type, g.series, g.summary, g.full_text, g.topics, g.status); } });
insertGuidanceAll();
console.log(`Inserted ${guidance.length} guidance documents`);

interface AdvisoryRow { reference: string; title: string; date: string; severity: string; affected_products: string; summary: string; full_text: string; cve_references: string; }

const advisories: AdvisoryRow[] = [
  {
    reference: "CFCS-ADV-2024-001", title: "Kritisk sarbarhed i Cisco IOS XE — aktivt udnyttet",
    date: "2024-01-20", severity: "critical",
    affected_products: JSON.stringify(["Cisco IOS XE", "Cisco routere", "Cisco switches"]),
    summary: "CFCS advarer om aktiv udnyttelse af en kritisk sarbarhed i Cisco IOS XE (CVE-2023-20198). Sarbarheden muliggorer uautoriseret adgang med de hojeste privilegier. Danske organisationer der anvender pavirket Cisco-udstyr bor anvende rettelser omgaende.",
    full_text: "CFCS er bekendt med aktiv udnyttelse af en kritisk sarbarhed i Cisco IOS XE Software (CVE-2023-20198, CVSS 10.0). Sarbarheden er i webgraensefladen og muliggorer en uautoriseret angriber at oprette en konto med niveau-15-privilegier (de hojeste privilegier). Pavirede versioner: Cisco IOS XE Software med aktiveret Web UI. Ojeblikkelige handlinger: (1) Deaktiver HTTP-serverfunktionen pa alle internetvendte systemer: no ip http server og no ip http secure-server. (2) Kontroller om uautoriserede konti med niveau-15-privilegier er oprettet. (3) Hvis kompromittering mistaenkes, gendan udstyret til en kendt god konfiguration. (4) Anven d Cisco-rettelser nar de er tilgaengelige. Anmeldelse: Organisationer der mistaenker kompromittering skal anmelde til CFCS.",
    cve_references: JSON.stringify(["CVE-2023-20198", "CVE-2023-20273"]),
  },
  {
    reference: "CFCS-ADV-2024-002", title: "DDoS-angreb mod dansk kritisk infrastruktur fra pro-russiske hacktivister",
    date: "2024-02-14", severity: "high",
    affected_products: JSON.stringify(["Offentlige myndigheder", "Finansiel sektor", "Transportinfrastruktur"]),
    summary: "CFCS advarer om et eskalerende monstre af DDoS-angreb mod dansk kritisk infrastruktur og offentlige myndigheder af pro-russiske hacktivistegrupper. Organisationer bor teste DDoS-beskyttelse og forbereder beredskabsplaner.",
    full_text: "CFCS har observeret et eskalerende antal DDoS-angreb (Distributed Denial of Service) mod danske malsaetninger. Truslen er isaer kommet fra pro-russiske hacktivistegrupper som KillNet, NoName057(16) og Anonymous Russia. Disse grupper koordinerer angreb via Telegram-kanaler og rekrutterer frivillige til at deltage i angrebene. De primere malsaetninger har vaeret: Offentlige myndigheders hjemmesider, finansielle institutioner, lufthavne og transportinfrastruktur, og medier. Angrebs karakteristik: Volumen-baserede DDoS-angreb typisk med kapacitet fra 10 Gbps til 100+ Gbps. Angrebene varer normalt 2-4 timer. Anbefalede foranstaltninger: Valider at DDoS-beskyttelse er aktiveret og konfigureret korrekt hos internetudbyderen eller via en cloudbaseret DDoS-mitigation-tjeneste. Test beredskabsplaner for DDoS-haendelser. Etabler kontakt med internetudbyderen om DDoS-respons-procedurer. Sikr at kritiske tjenester har redundante adgangsveje. Anmeld DDoS-angreb til CFCS.",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "CFCS-ADV-2024-003", title: "JetBrains TeamCity: Autentificerings-bypass sarbarhed under aktiv udnyttelse",
    date: "2024-03-05", severity: "critical",
    affected_products: JSON.stringify(["JetBrains TeamCity", "JetBrains TeamCity Cloud"]),
    summary: "CFCS advarer om aktiv udnyttelse af en autentificerings-bypass sarbarhed i JetBrains TeamCity (CVE-2024-27198). Sarbarheden giver uautoriseret adgang til TeamCity-servere. Organisationer med eksponerede TeamCity-instanser skal patche omgaende.",
    full_text: "En kritisk autentificerings-bypass sarbarhed (CVE-2024-27198, CVSS 9.8) er identificeret i JetBrains TeamCity. Sarbarheden muliggorer en uautoriseret angriber at fa administratoradgang til TeamCity-serveren og udfore vilkarlig kode. CFCS har bekraeftet udnyttelse mod danske organisationer. Dette er saerlig kritisk i softwareudviklingsmiljoer, da et kompromitteret TeamCity kan bruges til at indsatte ondsindet kode i softwareproduktionspipelines (supply chain attack). Pavirde versioner: JetBrains TeamCity til og med version 2023.11.3. TeamCity Cloud er patchet. Ojeblikkelige handlinger: (1) Opdater TeamCity til version 2023.11.4 eller nyere omgaende. (2) Hvis omgaende patching ikke er mulig, begrnens adgangen til TeamCity til kun betroede netvaerk. (3) Gennemga adgangslogge for tegn pa uautoriseret adgang. (4) Inspicer produktionspipelines for tegn pa misbrug.",
    cve_references: JSON.stringify(["CVE-2024-27198", "CVE-2024-27199"]),
  },
];

const insertAdvisory = db.prepare("INSERT OR IGNORE INTO advisories (reference, title, date, severity, affected_products, summary, full_text, cve_references) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
const insertAdvisoriesAll = db.transaction(() => { for (const a of advisories) { insertAdvisory.run(a.reference, a.title, a.date, a.severity, a.affected_products, a.summary, a.full_text, a.cve_references); } });
insertAdvisoriesAll();
console.log(`Inserted ${advisories.length} advisories`);

const guidanceCount = (db.prepare("SELECT count(*) as cnt FROM guidance").get() as { cnt: number }).cnt;
const advisoryCount = (db.prepare("SELECT count(*) as cnt FROM advisories").get() as { cnt: number }).cnt;
const frameworkCount = (db.prepare("SELECT count(*) as cnt FROM frameworks").get() as { cnt: number }).cnt;
console.log("\nDatabase summary:");
console.log(`  Frameworks:  ${frameworkCount}`);
console.log(`  Guidance:    ${guidanceCount}`);
console.log(`  Advisories:  ${advisoryCount}`);
console.log(`\nDone. Database ready at ${DB_PATH}`);
db.close();
