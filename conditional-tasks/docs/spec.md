# conditional-tasks — Спека

Эталонная игра класса B на форме `two-outcome`. Донор кладёт USDC в **один** эскроу и прикладывает текст
задания; получатель видит текст приватно, решает брать; взял (`accept`) — текст раскрыт публично; заявил
«готово» (`ready`) — окно голосования весом книги; подтвердили → деньги через сплиттер получателю +
репутация **донору**, иначе возврат донору. **Одна область = одно задание = один эскроу (`B=1`).**

Общие инварианты — `crown-spec/docs/games-harness.md`; здесь — вся специфика задания, дословно, чтобы
имплементация не требовала догадок.

## Область, идентификатор, резолвер

- **Область = задание**, ключ `scope_id = task_id` — **свободный** id (не адрес эскроу):
  ```
  task_id = sha256( "crown:conditional-tasks"
                  ‖ u8(len(canister_id)) ‖ canister_id
                  ‖ donor(32) ‖ recipient(32)
                  ‖ u64le(gross) ‖ i64le(deadline)
                  ‖ u16le(fee_bps) ‖ fee_wallet(32) ‖ u64le(nonce)
                  ‖ u64le(duration) ‖ u64le(voting_period) )
  ```
  То есть входы соли эскроу **минус `resolver`** + `canister_id` + тайминги. `task_id` коммитит `gross`
  и `deadline` (1:1: одна область — один эскроу).
- **Резолвер** = `key([task_id])` (threshold Ed25519, path `[task_id]`; локальная деривация из
  кешированного мастер-ключа, `get_resolver` — `query`).
- **Адрес эскроу** = `crown_derive::solana_pda_address(factory, [b"escrow", salt]).0`, где
  `salt = crown_salt::two_outcome(donor, recipient, gross, deadline, resolver, fee_bps, fee_wallet, nonce)`.
  `deadline` вне `i64` → `DeadlineOverflow`; все адреса ровно 32 байта иначе `BadFieldLength`.
- Круга нет: `task_id → resolver → адрес`. `text_hash` в `task_id` не входит — его несёт вызывающий и
  подпись донора (Register), канистра хранит только хеш.

## Состояния (`logic/`)

```
Created → { Accepted | Decided{Cancel} } ;  Accepted → { Decided{Cancel} | Voting } ;
Voting{started_at} → Decided{outcome} ;      Decided — поглощающее
outcome ∈ { Settle, Cancel }
```
`Created` — текст виден только получателю. `Accepted` — текст раскрыт публично. `Voting{started_at}` —
окно голосования. `Decided{outcome}` — терминал.

## Таблица переходов (полная, `logic/`)

`step(task, action, now)` сначала применяет **накопившиеся временные переходы** (`advance`), затем
действие. Временной переход персистится, даже если действие отвергнуто (провал действия ≡ `Tick`).
`match` исчерпывающий, без `_ =>`.

**Временные (`advance`), тайминги — §Тайминги:**
- `Created`/`Accepted`, `now ≥ cutoff` → `Decided{Cancel}`.
- `Voting`, `now ≥ voting_end` → `Decided{ verdict(votes) }`.
- Арифметика точки — `checked`; непредставима в `u64` → `Overflow` (состояние не меняется).
- `Decided` — неизменно.

**Действия:**

| Состояние × Действие | Результат |
|---|---|
| `Created` × `Accept` | → `Accepted` (текст раскрыт) |
| `Created` × `Decline` | → `Decided{Cancel}` |
| `Accepted` × `Decline` | → `Decided{Cancel}` (досрочно освобождает деньги донора) |
| `Accepted` × `Ready` | → `Voting{started_at: now}` |
| `Voting` × `Vote(v)` | `v.weight < MIN_VOTE_WEIGHT` → `WeightBelowThreshold`; `v.voter` уже голосовал → `DuplicateVoter`; иначе `votes.push(v)` |
| любое × `Tick` | только временные переходы |
| `Created` × {`Ready`,`Vote`} | `InvalidTransition` |
| `Accepted` × {`Accept`,`Vote`} | `InvalidTransition` |
| `Voting` × {`Accept`,`Decline`,`Ready`} | `InvalidTransition` |
| `Decided` × {`Accept`,`Decline`,`Ready`,`Vote`} | `InvalidTransition` |

Ошибки шага: `InvalidTransition · WeightBelowThreshold · DuplicateVoter · Overflow`.

## Правило вердикта (дословно)

`Settle` ⇔ `Σвес(done)` **строго** больше `Σвес(not_done)`. Иначе `Cancel`, включая: **ничью**
(`Σdone == Σnot_done`), **пустое голосование**, **переполнение** суммирования весов (`checked_add`; при
переполнении немедленно `Cancel`). **Кворума нет.** Подсчёт тотален: задание всегда финализируется в
`Decided`, не застревает в `Voting`.

## Тайминги (якорь на ончейн-`deadline`)

Эскроу `two-outcome` не несёт времени рождения — только `deadline`. Поэтому окна выводятся из `deadline`
как чистая функция `f(голоса, deadline, now)` (без create-clock, без таймера):
- **Отсечка accept/ready** (кэнсел `Created`/`Accepted`): `cutoff = deadline − voting_period − DEADLINE_MARGIN`.
  При `now ≥ cutoff` без `Ready` → `Cancel`.
- **Конец окна голосования** (тали `Voting`): `voting_end = deadline − DEADLINE_MARGIN`.
- `duration` в соль эскроу не входит; его несёт вызывающий + подпись донора и он проверяется лишь
  неравенством дедлайна при регистрации (§Валидация); самим отсечением служит `deadline`.
- `DEADLINE_MARGIN` (72 ч) гарантирует зазор между вердиктом и открытием `refund()`.

## Валидация регистрации (порядок и отказы)

`ProfileDisabled` (профиль `enabled=false`) → `GrossBelowFloor` (`gross <` игровой флор) →
`GrossBelowMinimum` (`gross < profile.min_gross`) → `ReputationBelowMinimum` (репутация донора **по
пруфу** `< profile.min_reputation`; пруф требуется **только** если `min_reputation > 0`) →
`DurationOutOfRange` (`duration ∉ [MIN_DURATION, MAX_DURATION]`) → `DeadlineTooTight`
(`deadline < now + duration + voting_period + DEADLINE_MARGIN`; арифметика `checked`, переполнение →
`TimeOverflow`). Граница точная: ровно минимум проходит, минус секунда — отказ.

## Константы

| Константа | Значение | Роль |
|---|---|---|
| `LOGIC_VERSION` | `4` | версия правил (меняется только осознанной правкой машины/вердикта) |
| `MIN_DURATION` | `60` (1 мин) | нижняя граница `duration` |
| `MAX_DURATION` | `2_592_000` (30 сут) | верхняя граница `duration` |
| `DEADLINE_MARGIN` | `259_200` (72 ч) | зазор дедлайна над окном голосования |
| `MIN_VOTE_WEIGHT` | `100_000` | мин. вес голоса (minor units репутации, USDC 6 знаков) |
| `VOTING_PERIOD` | конфиг-константа, вшивается в `task_id`: `3600` (mainnet) / `120` (devnet) | длина окна голосования; смена не трогает созданные |
| `min_gross` | дефолт `1_860_000` (≈$1.86 = tasks be × (1+MARGIN), `cost.md §5`); обязан быть ≥ индексного `MIN_GROSS`; финально пиннится на cost-gate | флор приёма игры |
| `fee_bps` / `fee_wallet` | дефолт `300` (3%) / кошелёк создателя | прейскурант, входит в соль эскроу |

Флор формы `gross ≥ 1` проверяет фабрика при `create_escrow`, не канистра.

## Форматы подписываемых сообщений (замороженный протокол)

`DOMAIN = "crown:conditional-tasks:v1"`. Ed25519 кошельком (`verify_strict`), адрес ≡ pubkey (32 б),
подпись 64 б. Одно поле на строку, `key: value`, фиксированный порядок; печатный ASCII; кодирование
инъективно (пиннится юнит-тестами).

**Задание:**
```
crown:conditional-tasks:v1
action: <register|accept|decline|ready|vote>
chain: <chain id>
canister: <principal>
task: <bs58(task_id)>
```
`register` добавляет `text: <hex(text_hash)>` и `duration: <dec>`; `vote` добавляет `choice: <done|not_done>`.

**Профиль:**
```
crown:conditional-tasks:v1
action: set-profile
chain: <chain id>
canister: <principal>
recipient: <bs58>
min_gross: <dec>
min_reputation: <dec>
enabled: <true|false>
counter: <dec>
```

**Вердикт (в `claim`, побайтово, `games-harness.md §5`):**
`verdict_message = "crown:two-outcome:<cluster>" ‖ program_id(32) ‖ u8(outcome)`, `outcome`: `settle=0`,
`cancel=1`. Подпись — `key([task_id])`; проверяется против поля `resolver` эскроу. Одна подпись на область
(при `B=1` — на её единственный эскроу).

## Профиль и ручки получателя

`set_profile` подписью получателя со **строго возрастающим** `counter` (равный/меньший → `stale counter`).
`min_gross` обязан быть ≥ игрового флора (иначе `profile minimum below the game floor`). Параметры
фиксируются в задании при рождении; смена задним числом не влияет на созданные. **Профиль по умолчанию**
(незаданный, ленивая материализация): `min_gross = флор`, `min_reputation = 0`, `enabled = true`,
`counter = 0` — приём разрешён по умолчанию (получатель просто никогда не примет).

## Терминальные исходы: деньги / комиссия / репутация

| Исход | Деньги | Комиссия | `Settled` | Репутация |
|---|---|---|---|---|
| `settle` (0), `claim(0,sig)` | `fee → fee_wallet`; `splitter.donate(recipient, gross − fee)` | `fee = gross·fee_bps/10000` | `payer = escrow` | **донору**, `= gross − fee` (прошедшее через сплиттер; комиссия в книгу не попадает) |
| `cancel` (1), `claim(1,sig)` | 100% → донор | нет | нет | нет |
| `refund()` (ончейн, кто угодно, строго после `deadline`) | 100% → донор | нет | нет | нет |

Репутация — только донору, только при исполненном `claim(0)`; отказ/таймаут/`refund` не дают ничего.
Заработать больше внесённого нельзя.

## Крайние случаи (обязаны сохраниться)

- Двойной `accept` → `InvalidTransition`, состояние остаётся `Accepted`.
- `decline` из `Created` **и** из `Accepted` → `Cancel`.
- `vote` после конца окна → окно тальится первым, голос отвергнут, вердикт записан.
- Повторный `ready`, `ready`/`vote` из `Created`, `vote` из `Accepted`, любое действие из `Decided` → отказ.
- `accept` в последнюю секунду до `cutoff` — работает; ровно в `cutoff` — уже `Cancel`.
- Дубль голосующего `(task_id, voter)` / вес `< MIN_VOTE_WEIGHT` → отказ, счёт не меняется.
- Дубль `task_id` при регистрации → отказ (материализация идемпотентна).
- Переполнение суммы весов → `Cancel`; переполнение арифметики часов → ошибка, состояние не тронуто.
- Иммутабельность вердикта: исход пишется до первой подписи; ретрай подписывает тот же исход.
- `donor == recipient` — **не блокируется** (как в оригинале; самодонат — принятое ограничение).

## Методы (`.did`, фиксирован)

`register_task` · `accept` · `decline` · `ready` · `vote` · `set_profile` · `request_signature` ·
queries (`get_task`, `get_verdict` (`null` до `Decided`), `get_resolver` (`query`),
`get_profile`, `get_logic_version`). Порядок `vote`: подпись → время(`Tick`) → состояние `Voting` →
дедуп `(task_id, voter)` → пруф веса (локально, `MIN_VOTE_WEIGHT`).

**Граница (`inspect_message`, харнесс §6):** каждый меняющий состояние вызов доказывает применимость до
раунда — `register_task` пруфом рождения (дорогая BLS не идёт реплицируемо на мусор), `accept`/`decline`/
`ready` подписант ≡ получатель + состояние допускает, `set_profile` кэп + флор, `vote` пруф веса + порог.
Обречённое отбивается не-реплицируемо; `update` остаётся авторитетным (дедуп/кэп/машина состояний).

Query состояния игры **не сертифицированы** (`+witness` снят по всему проекту): доверие в Crown течёт через
threshold-подпись резолвера (проверяется on-chain) и сертифицированные пруфы **индекса** (книга/рождения),
а не через состояние канистры-игры — деньги эскроу клеймит против подписи, не против query. Трастовое чтение
состояния игры, если понадобится, — отдельный версионный метод, не часть замороженного ядра.

Плюс два операционных метода вне пользовательского протокола:
- `init(opt InitArgs{index, nns_root_key})` — конструктор: на testnet override principal индекса + NNS
  root key (PocketIC/тест-IC отличаются от mainnet); на mainnet override **трапает** (пиннутый конфиг +
  IC root key — источник истины).
- `bootstrap()` — одноразовый (идемпотентный) фетч мастер-Schnorr-ключа (`schnorr_public_key`) после
  деплоя; `init` синхронен и таймеры запрещены, поэтому кеш ключа заполняется явным setup-вызовом, до
  первого `get_resolver`.

## Специфика харденинга (дельты к харнессу)

- **Слепа:** внешние сети не читает; вердикт для несуществующего эскроу безвреден и закрыт гейтом рождения.
- **Ленивое создание:** `register_task` — деривация `task_id`, пишет ноль; запись материализуется на
  первом эскроу с пруфом рождения. Триггер материализации — пруф рождения (не самоподпись). `duration`,
  `text_hash` + Register-подпись донора несёт материализующий вызов; `min_reputation`-проверка (если
  `>0`) — по пруфу репутации донора, локально.
- **Без таймера:** отсечка и конец окна — чистые функции от `deadline` (§Тайминги). Подпись — оплаченный pull.

## DoD / тесты (`crown-spec/docs/01-standards.md §Тесты 8,9,12`)

`logic/` zero-dep, property-тесты: settle-строго-больше, ничья→cancel, пусто→cancel, переполнение→cancel;
`failed_action_is_a_tick`; `decided_is_absorbing`; граница `cutoff`/`voting_end` точная; `Overflow` не
двигает состояние. Слепа (grep сетей пуст). Ленивое создание: без пруфа рождения — ноль записи. Граница:
обречённый вызов (плохой пруф рождения/веса, не тот подписант, пере-кэп) отбит в `inspect_message`, до
реплицируемого `update`; голос — дедуп `(task_id, voter)`. Одна подпись области над
`(DOMAIN‖program‖outcome)`, проверяется против `resolver` эскроу. Форматы сообщений пиннуты. Текст —
только хеш в канистре. E2e через реальную сеть.
