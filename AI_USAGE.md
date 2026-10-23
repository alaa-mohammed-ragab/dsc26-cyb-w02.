# AI usage: dsc26-cyb-w02

## Tools

I used ChatGPT to understand the task requirements, learn how STRIDE applies to different element types, and implement the Python functions. I also used it to review the YAML model and identify fields that needed to match the code. I verified the implementation by running the test suite and checking the model with the command-line tool.

## What AI got wrong

ChatGPT initially used `ref` to link threats to elements and `pii` to identify personal data stores. These assumptions did not match my YAML file, which uses `target` and `holds_pii`. I corrected the field names and checked the model output again. This taught me to verify AI suggestions against the actual project structure instead of assuming they are correct.

## In my own words

1. Why does a data store have no Spoofing threats in STRIDE per element, and where does that threat go instead?

A data store stores data, so Spoofing is not normally applicable to it as an element. Spoofing applies to an identity, such as an external entity or a process that an attacker could impersonate. For a data store, threats such as Tampering and Information Disclosure are more directly relevant.

2. Which of your eleven new threats would you fix first, and why that one?

I would fix T33 first because an attacker could modify account features and make the system less effective at detecting mule accounts. This could allow suspicious transfers to go unnoticed and cause financial losses.