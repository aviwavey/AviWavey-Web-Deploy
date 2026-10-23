import{c as s}from"./index-ckj5zNSj.js";import{d as o}from"./PaymentPortal-CevfQ4Bu.js";/**
 * @license lucide-react v1.16.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const n=[["path",{d:"M7 7h10v10",key:"1tivn9"}],["path",{d:"M7 17 17 7",key:"1vkiza"}]],c=s("arrow-up-right",n);async function i(t=50,a=0){return o.get(`/api/v1/payouts?limit=${t}&offset=${a}`)}async function p(t,a){return o.post(`/api/v1/payouts/${t}/cancel`,{reason:a})}async function u(t,a){return o.post(`/api/v1/payouts/${t}/hold`,{reason:a})}async function y(t){return o.post(`/api/v1/payouts/${t}/release-hold`)}export{c as A,p as c,u as h,i as l,y as r};
