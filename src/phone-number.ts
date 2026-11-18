import {parsePhoneNumberFromString, getCountries, getCountryCallingCode, type CountryCode} from 'libphonenumber-js/max';
export {getCountries, getCountryCallingCode};
export type {CountryCode};
/** Valid numbering plan, not proof of ownership or reachability. Keep trunk-prefix rules country-specific. */
export function parseTelephone(raw:string, country?:CountryCode) {
 const value=raw.trim();
 if(!value || value.length>80 || /[A-Za-z#;]/.test(value)) return undefined;
 const phone=parsePhoneNumberFromString(value,{defaultCountry:country,extract:false});
 return phone && !phone.ext && phone.isValid() ? phone : undefined;
}
export function normalizeTelephone(raw:string,country?:CountryCode):string {
 const phone=parseTelephone(raw,country);
 if(!phone)throw new Error('INVALID_TELEPHONE');
 return phone.number;
}
