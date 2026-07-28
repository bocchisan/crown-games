# conditional-funding — Спека

Краудфандинг-сбор на форме `two-outcome`. Получатель открывает сбор (`goal` — дисплей, ничего не гейтит,
+ `duration`); доноры скидываются — каждый **одной транзакцией** в свой эскроу, **без подписи канистре**
(сама транзакция — участие). Получатель жмёт «готово» (`ready`) → голосование держателей репутации.
Подтвердили → **всем** эскроу через сплиттер получателю + репутация каждому донору; иначе **всем**
возврат. **Тишина = возврат.** Область = сбор, `B=N`.

Общие инварианты — `crown-spec/docs/games-harness.md`; здесь — вся специфика сбора, дословно.

## Область, идентификатор, резолвер, членство

- **Область = сбор**, ключ `scope_id = collection_id` — **свободный** id (не адрес эскроу):
  ```
  collection_id = sha256( "crown:conditional-funding"
                        ‖ u8(len(canister_id)) ‖ canister_id
                        ‖ recipient(32) ‖ u64le(recipient_nonce)
                        ‖ u64le(duration) ‖ u64le(voting_period)
                        ‖ u16le(approval_threshold) ‖ u128le(quorum_weight) )
  ```
  Конфиг/тайминги — в прообразе (снимок правил закоммичен создателем; при материализации канистра
  пересчитывает `collection_id` из предъявленных полей и сверяет). `collection_id` **не** коммитит
  `gross`/`deadline` (много эскроу одной области). `recipient_nonce` лишь разводит `id`.
- **Резолвер** = `key([collection_id])` (локальная деривация, `get_resolver` — `query`).
- **Членство эскроу — полем `resolver`, не `nonce`** (реестра нет): у каждого вклада
  `salt = crown_salt::two_outcome(donor, recipient, gross, deadline, resolver, fee_bps, fee_wallet, nonce)`,
  где `recipient`/`resolver` — из записи сбора, `fee_bps`/`fee_wallet` — из конфига, не из аргументов;
  адрес = `crown_derive::solana_pda_address(factory, [b"escrow", salt]).0`. `deadline u64→i64`, вне
  диапазона → `DeadlineOverflow`. Чужой получатель/резолвер невыводимы; иная комиссия/резолвер → другой
  адрес, в сбор не входит. (Усечённый хеш в `nonce` вскрываем перебором ~2^64/N — поэтому привязка
  только `resolver`.)

## Состояния (`logic/`)

```
Funding → Voting{started_at} → Decided{outcome} ;  Decided — поглощающее
outcome ∈ { Settle, Refund }
```
Рождение всегда в `Funding`, `votes` пуст. Действия: `Ready`, `RecipientCancel`, `Vote(v)`, `Tick`.
(`Refund` здесь — это `outcome=1` формы `two-outcome`, которую фабрика зовёт `cancel`; байт и вердикт-сообщение общие, `games-harness §5`.)

## Таблица переходов (полная, `logic/`)

Время применяется **до** действия (лениво); опоздавший вызов действию не помогает; провалившееся
действие сохраняет уже наступивший временной переход. Границы строго `>=` (момент границы — следующей фазе).

| Состояние (условие) | `ready` | `recipient_cancel` | `vote(v)` | время |
|---|---|---|---|---|
| `Funding`, `now < created_at+duration` | → `Voting{now}` | → `Decided{Refund}` | `InvalidTransition` | — |
| `Funding`, `now ≥ created_at+duration` | → `Decided{Refund}`, затем `InvalidTransition` | то же | то же | → `Decided{Refund}` |
| `Voting`, `now < started_at+voting_period` | `InvalidTransition` | `InvalidTransition` | `w<MIN_VOTE_WEIGHT`→`WeightBelowThreshold`; дубль→`DuplicateVoter`; иначе запись | — |
| `Voting`, `now ≥ started_at+voting_period` | тэлли→`Decided`, затем `InvalidTransition` | то же | то же | → `Decided{verdict(votes)}` |
| `Decided` | `InvalidTransition` | `InvalidTransition` | `InvalidTransition` | — |

`ready`/`recipient_cancel` на неоматериализованном сборе (ни одного эскроу) → `unknown collection`.
`checked_add` для `created_at+duration` и `started_at+voting_period`; переполнение → `Overflow`
(состояние не двигается). Ошибки шага: `InvalidTransition · WeightBelowThreshold · DuplicateVoter · Overflow`.

## Правило вердикта (дословно) — с кворумом

```
yes = Σвес(done);  no = Σвес(not_done)      // checked_add; переполнение → refund
turnout = yes + no                           // checked_add; переполнение → refund
turnout < quorum_weight                       → refund
share = yes · 10000;  bar = approval_threshold · turnout   // checked_mul; переполнение → refund
settle ⇔ share > bar    (строго >)
иначе                                         → refund
```
- **Кворум** `quorum_weight` — абсолютный вес в minor units, считается по **обеим** сторонам (`yes+no`),
  не доля собранного (канистра слепа). **Порог одобрения** `approval_threshold` — десятитысячные, строгое
  `>`. `5000` = строгое большинство.
- Ничья, недобор кворума, пустое голосование, любое переполнение подсчёта → **refund** (сбор всегда
  финализируется). `settle`→`outcome=0`, `refund`→`outcome=1`.

## Тайминги

- `created_at` — **слот рождения первого профинансированного вклада** (детерминирован, из пруфа
  рождения; слот→время линейно по пиннутому якорю: `created_at = genesis_unix + (slot − genesis_slot)·slot_ms/1000`,
  где `slot_ms = 1000/SLOTS_PER_SECOND`; `slot_ms`/`genesis_slot`/`genesis_unix` — поля `config/`-профиля,
  изолированы в `config::slot_to_created_at`, checked; плейсхолдеры до F5(devnet)/P8(mainnet), фриз-гейт
  `genesis_unix≠0` на mainnet), фиксируется при материализации. Окно `Funding`:
  `[created_at, created_at + duration]`. `ready`/`recipient_cancel` валидны при `now < created_at+duration`.
- `started_at` — канистерное время нажатия `ready`. Окно `Voting`: `[started_at, started_at+voting_period]`.
- `goal` в код не входит; оверфандинг свободен; выплата = Σ собранного − комиссия (сумму считает сервер
  из цепи, канистра — нет).
- `deadline` каждого эскроу ≥ `created_at + duration + voting_period + DEADLINE_MARGIN` (72 ч) — обеспечивает
  UI донора (регистрации нет), иначе `refund()` обгонит `claim(settle)`.

## Константы и профиль

| Константа | Значение |
|---|---|
| `LOGIC_VERSION` | `3` |
| `MIN_DURATION` | `60` (1 мин), граница включительна |
| `MAX_DURATION` | `7_776_000` (90 сут) |
| `MIN_VOTE_WEIGHT` | `100_000` |
| `MIN_APPROVAL_THRESHOLD` | `5_000` (нижняя граница включительно) |
| `APPROVAL_THRESHOLD_SCALE` | `10_000` (знаменатель и верхняя граница исключительно) |
| `DEADLINE_MARGIN` | `72 ч` (забота UI, не в `logic/`) |

Создание: `duration ∈ [MIN_DURATION, MAX_DURATION]` (иначе `DurationOutOfRange`);
`approval_threshold ∈ [5000, 10000)` (иначе `ThresholdOutOfRange`).

Профиль (снимок при рождении, входит в прообраз `id`):

| Профиль | `voting_period` | `approval_threshold` | `quorum_weight` |
|---|---|---|---|
| devnet | `120` | `5000` | `150_000` |
| mainnet | `3600` | `5000` | `1_000_000` |

Валидация при деплое: `approval_threshold ∈ [5000,10000)`; `quorum_weight ≥ MIN_VOTE_WEIGHT`;
`fee_bps < 10000`; `domain` непуст; `id` непуст, `ascii_graphic`, без `:` и `\n`; цепи попарно различны
по `(id, domain, factory)`; `factory`/`fee_wallet` base58 → 32 байта. Конфиг: `crown_index, threshold_key,
voting_period, approval_threshold, quorum_weight`; per-chain `id, factory, domain, fee_bps, fee_wallet`.
Нет: сплиттер, казна, RPC-URL, `min_gross`.

## Форматы сообщений

**Кошельковая подпись участника** — UTF-8, одно поле на строку, `key: value`, фиксированный порядок:
```
crown:conditional-funding:v1
action: <create|ready|cancel|vote>
chain: <id>
canister: <principal>
collection: <hex(collection_id)>
goal: <dec>          # только create
duration: <dec>      # только create
choice: <done|not_done>   # только vote
```
`DOMAIN = "crown:conditional-funding:v1"` (версионный). Слова заморожены. Проверка: signer 32 байта,
Ed25519 `verify_strict`, адрес = pubkey. Кодирование инъективно (тест).

**Вердикт (в `claim`, побайтово, `games-harness.md §5`):**
`verdict_message = "crown:two-outcome:<cluster>" ‖ program_id(32) ‖ u8(outcome)`, `outcome`: `settle=0`,
`refund=1`. **Одна подпись** сбора `key([collection_id])` над этим сообщением — переиспользуется всеми N
эскроу (у всех `resolver = key([collection_id])`); проверяется on-chain против поля `resolver`. Это и есть
атомарность: один `outcome` на все эскроу сбора, без Merkle-корня/пути.

## Методы (`.did`, фиксирован)

`create_collection` · `ready` · `recipient_cancel` · `vote` · `request_signature` · queries
(`get_collection`, `get_resolver` (`query`), `get_logic_version`). Плюс инфраструктурные (как в
tasks): `init(opt InitArgs)` (testnet-оверрайды index/NNS-root, на mainnet — trap) и `bootstrap()` —
одноразовый идемпотентный фетч мастер-Schnorr-ключа (`schnorr_public_key`) после деплоя (sync `init` не
может, таймеры запрещены).

Query состояния игры **не сертифицированы** (`+witness` снят по всему проекту): доверие в Crown течёт через
threshold-подпись резолвера (проверяется on-chain) и сертифицированные пруфы **индекса** (книга/рождения),
а не через состояние канистры-игры — деньги эскроу клеймит против подписи, не против query.
`request_signature(chain, collection_id)`: если `Decided` — оплаченный pull производит **одну** подпись
сбора (кэш по `collection_id`), возвращает `(outcome, sig)`; иначе `collection not decided`. Порядок
`vote`: подпись → время(`Tick`) → состояние `Voting` → дедуп `(collection_id, voter)` → пруф веса;
валидность — в `inspect_message`.

**Граница (`inspect_message`, харнесс §6):** каждый меняющий состояние вызов доказывает применимость до
раунда — `create_collection` с пруфом рождения материализует (дорогая BLS не идёт реплицируемо на мусор;
без пруфа — чистое эхо, ноль записи), `ready`/`recipient_cancel` — подписант ≡ получатель + состояние,
`vote` пруф веса + порог. Обречённое отбивается не-реплицируемо; `update` авторитетен.

## Терминальные исходы: деньги / комиссия / репутация

| Исход | Деньги (на каждый эскроу) | Комиссия | `Settled` | Репутация |
|---|---|---|---|---|
| `settle` (0) | `fee → fee_wallet`; `splitter.donate(recipient, gross − fee)` | `gross·fee_bps/10000` | `payer = escrow` | **донору вклада**, `= gross − fee` |
| `refund` (1) | 100% → донор | нет | нет | нет |
| `refund()` (ончейн, после `deadline`, кто угодно) | 100% → донор | нет | нет | нет |

Получатель получает `Σ gross − Σ комиссий`, не больше; приза нет. Клеймы независимы (батч `K` на транзакцию).

## Специфика харденинга и крайние случаи

- **Ленивое создание:** `create_collection` — деривация `id`+резолвера, пишет ноль; материализуется на
  **первом профинансированном вкладе** (пруф рождения); там же фиксируется `created_at` (слот). Снимок
  профиля — в прообразе. `ready`/`recipient_cancel` **не** материализуют (самоподписаны, бесплатны).
- **Без таймера:** окна и тэлли — чистые функции; safety — ончейн-`refund()`.
- Отмена — **только из `Funding`** (после «готово» двери нет); досрочного выхода донора нет.
- Оверфандинг свободен; `goal` — дисплей.
- `donor == recipient` и самоголосование не запрещены (сдерживаются публичностью).
- Вес голоса — репутация у получателя на момент голоса (снапшота нет), чейн-локально; докупка во время
  голосования ретроактивно не учитывается.
- «Стоящий вердикт»: эскроу, деривуемый к сбору, получает его исход, когда бы ни родился. Частичное
  исполнение: неклеймленный эскроу жив с целым `gross`, репутации не даёт, выходит `refund()` по `deadline`.
- «Готово» — заявление, не пруф; сдачу подтверждают голосующие.

## DoD / тесты (`crown-spec/docs/01-standards.md §Тесты 8,9,12`)

`logic/` zero-dep, property-тесты вердикта (кворум по обеим сторонам, строгое большинство, ничья/недобор
→ refund, переполнение → refund); границы окна точные; `Overflow` не двигает состояние. Слепа, без
реестра. Ленивое создание: `create`/`ready`/`cancel` без пруфа рождения — ноль записи. Атомарность: одна
подпись сбора на все N эскроу, один `outcome`. Граница: обречённый вызов (плохой пруф рождения/веса, не
тот подписант) отбит в `inspect_message`, до реплицируемого `update`; голос — дедуп
`(collection_id, voter)`. `collection_id`-кодировка пиннута вектором. E2e через реальную сеть.
