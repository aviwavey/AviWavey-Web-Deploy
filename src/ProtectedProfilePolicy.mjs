export const privateGender=value=>['male','female','other','prefer_not_to_say'].includes(value);
export function protectedDetailsMatch(lock,input){return !lock||lock.first_name===input.firstName&&lock.last_name===input.lastName&&lock.birthdate===input.birthdate&&lock.address===input.address&&lock.gender===input.gender;}
export async function assertMobileChangeAllowed(sql,userId,value){
 const table=await sql`SELECT to_regclass('public.truemark_verified_identity') AS name`;
 if(!table[0]?.name)return;
 const locked=await sql`SELECT owner_id FROM truemark_verified_identity WHERE owner_id=${userId}`;
 if(!locked.length)return;
 const contacts=await sql`SELECT normalized_value FROM contacts WHERE user_id=${userId} AND kind='telephone'`;
 if(!contacts.some(c=>c.normalized_value===value))throw new Error('IDENTITY_DETAILS_LOCKED');
}
