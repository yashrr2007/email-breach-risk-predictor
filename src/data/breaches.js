/**
 * Mock breach intelligence database.
 * Shape mirrors what a real integration (HaveIBeenPwned / XposedOrNot) would return,
 * so swapping in a live provider later only touches src/services/breachService.js.
 *
 * Each breach: site, breachDate, addedDate, dataClasses, accounts, severity (0-10),
 * verified, description.
 */
const BREACHES = [
  {
    id: 'collection1',
    site: 'Collection #1',
    domain: '---',
    breachDate: '2019-01-07',
    addedDate: '2019-01-16',
    dataClasses: ['Email addresses', 'Passwords'],
    accounts: 772904991,
    severity: 9,
    verified: true,
    description: 'Massive credential-stuffing corpus of email/password pairs circulated on hacking forums.'
  },
  {
    id: 'linkedin-2021',
    site: 'LinkedIn',
    domain: 'linkedin.com',
    breachDate: '2021-06-22',
    addedDate: '2021-06-26',
    dataClasses: ['Email addresses', 'Names', 'Phone numbers', 'Geolocation', 'Job titles', 'Salutations', 'Social media profiles'],
    accounts: 700000000,
    severity: 7,
    verified: true,
    description: 'Scraped data of 700M LinkedIn users was put up for sale on a dark web forum.'
  },
  {
    id: 'facebook-2019',
    site: 'Facebook',
    domain: 'facebook.com',
    breachDate: '2019-08-01',
    addedDate: '2021-04-04',
    dataClasses: ['Email addresses', 'Names', 'Phone numbers', 'Locations', 'Relationship statuses', 'Genders'],
    accounts: 533000000,
    severity: 6,
    verified: true,
    description: 'Phone-number-linked profiles of 533M users leaked, later republished for free.'
  },
  {
    id: 'adobe-2013',
    site: 'Adobe',
    domain: 'adobe.com',
    breachDate: '2013-10-04',
    addedDate: '2013-12-04',
    dataClasses: ['Email addresses', 'Password hints', 'Passwords', 'Usernames'],
    accounts: 152445165,
    severity: 9,
    verified: true,
    description: 'Adobe breach exposed 152M accounts with poorly encrypted passwords and plaintext hints.'
  },
  {
    id: 'canva-2019',
    site: 'Canva',
    domain: 'canva.com',
    breachDate: '2019-05-24',
    addedDate: '2019-08-09',
    dataClasses: ['Email addresses', 'Names', 'Passwords', 'Usernames', 'Cities', 'Countries of residence'],
    accounts: 137272116,
    severity: 7,
    verified: true,
    description: 'Attackers stole user data including bcrypt-hashed passwords for 137M Canva accounts.'
  },
  {
    id: 'dropbox-2012',
    site: 'Dropbox',
    domain: 'dropbox.com',
    breachDate: '2012-07-01',
    addedDate: '2016-08-31',
    dataClasses: ['Email addresses', 'Passwords'],
    accounts: 68648009,
    severity: 8,
    verified: true,
    description: '68M Dropbox credentials stolen; half were bcrypt-hashed, half salted SHA-1.'
  },
  {
    id: 'myfitnesspal-2018',
    site: 'MyFitnessPal',
    domain: 'myfitnesspal.com',
    breachDate: '2018-02-01',
    addedDate: '2019-02-21',
    dataClasses: ['Email addresses', 'IP addresses', 'Passwords', 'Usernames'],
    accounts: 143606147,
    severity: 7,
    verified: true,
    description: '143M MyFitnessPal accounts exposed with SHA-1 hashed passwords.'
  },
  {
    id: 'zomato-2017',
    site: 'Zomato',
    domain: 'zomato.com',
    breachDate: '2017-05-17',
    addedDate: '2017-05-18',
    dataClasses: ['Email addresses', 'Passwords'],
    accounts: 17009398,
    severity: 6,
    verified: true,
    description: '17M Zomato accounts stolen from an internal developer machine.'
  },
  {
    id: 'dominos-2019',
    site: 'Dominos India',
    domain: 'dominos.co.in',
    breachDate: '2021-04-10',
    addedDate: '2021-04-20',
    dataClasses: ['Email addresses', 'Names', 'Phone numbers', 'Physical addresses', 'Orders'],
    accounts: 18000000,
    severity: 6,
    verified: true,
    description: '13TB of Dominos India order data including customer contact details leaked.'
  },
  {
    id: 'bigbasket-2020',
    site: 'BigBasket',
    domain: 'bigbasket.com',
    breachDate: '2020-10-30',
    addedDate: '2020-11-06',
    dataClasses: ['Email addresses', 'Names', 'Phone numbers', 'Physical addresses', 'Dates of birth'],
    accounts: 9800000,
    severity: 6,
    verified: true,
    description: 'Personal data of 9.8M BigBasket customers put up for sale on the dark web.'
  },
  {
    id: 'tweetscrapper-2022',
    site: 'Twitter Scrape',
    domain: 'twitter.com',
    breachDate: '2022-01-01',
    addedDate: '2022-11-30',
    dataClasses: ['Email addresses', 'Names', 'Usernames'],
    accounts: 211524284,
    severity: 4,
    verified: true,
    description: 'API-vulnerability scrape exposing 211M Twitter profiles with public data.'
  },
  {
    id: 'wattpad-2020',
    site: 'Wattpad',
    domain: 'wattpad.com',
    breachDate: '2020-06-29',
    addedDate: '2020-07-19',
    dataClasses: ['Email addresses', 'Names', 'Passwords', 'Usernames', 'Dates of birth', 'Genders', 'Social media profiles'],
    accounts: 26876549,
    severity: 7,
    verified: true,
    description: '27M Wattpad accounts leaked including bcrypt password hashes.'
  },
  {
    id: 'quentin-2023',
    site: 'Quin',
    domain: 'quin.com',
    breachDate: '2023-04-01',
    addedDate: '2023-05-02',
    dataClasses: ['Email addresses', 'Names', 'Passwords', 'IP addresses'],
    accounts: 830000,
    severity: 5,
    verified: false,
    description: 'Smaller startup breach with unhashed passwords allegedly circulated privately.'
  },
  {
    id: 'cred-stuff-2024',
    site: 'Credential Stuffing Dump',
    domain: '---',
    breachDate: '2024-11-15',
    addedDate: '2025-01-08',
    dataClasses: ['Email addresses', 'Passwords'],
    accounts: 15000000,
    severity: 9,
    verified: false,
    description: 'Fresh credential-stuffing combo list aggregated from multiple 2024 attacks.'
  }
];

/** Deterministic pseudo-breach assignment for emails not present in samples. */
const SAMPLE_KNOWN_EMAILS = {
  'john.doe@gmail.com': ['collection1', 'linkedin-2021', 'adobe-2013'],
  'jane@gmail.com': ['linkedin-2021', 'facebook-2019'],
  'admin@company.com': ['collection1', 'dropbox-2012', 'cred-stuff-2024'],
  'test@test.com': ['tweetscrapper-2022'],
  'priya.sharma@gmail.com': ['zomato-2017', 'bigbasket-2020', 'dominos-2019'],
  'rahul.verma@gmail.com': ['linkedin-2021', 'canva-2019'],
  'victim@example.com': ['collection1', 'adobe-2013', 'dropbox-2012', 'cred-stuff-2024']
};

module.exports = { BREACHES, SAMPLE_KNOWN_EMAILS };
