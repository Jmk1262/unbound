/*
 * util/extended_error.c - Handling extended DNS errors
 *
 * Copyright (c) 2019, NLnet Labs. All rights reserved.
 *
 * This software is open source.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "util/extended_error.h"
#include "util/regional.h"
#include "sldns/sbuffer.h"
#include "util/data/msgreply.h"

int extended_error_register(struct regional* region,
	struct extended_error** first, uint16_t flags, int rcode, int icode,
	char* extra_text)
{
	struct extended_error* e;
	e = (struct extended_error*)regional_alloc(region, sizeof(*e));
	e->flags = flags;
	e->code = (uint16_t)icode;
	e->code |= ((uint16_t)rcode << 12);
	if(extra_text)
		e->extra_text = regional_strdup(region, extra_text);
	else
		e->extra_text = NULL;
	e->next = NULL;

	verbose(VERB_OPS, "extended error registered");

	/* add to qstate linked list */
	if(!*first)
		*first = e;
	else {
		struct extended_error* l = *first;
		while(l->next) 
			l = l->next;
		l->next = e;
	}
	return 1;
}

int extended_error_append_options(struct extended_error* e,
	struct edns_data* edns_out, struct regional* region)
{
	size_t extratextlen = 0;
	sldns_buffer* buf = sldns_buffer_new(BUFSIZ);
	while(e) {
		verbose(VERB_OPS, "extended error option appended");
		sldns_buffer_clear(buf);
		sldns_buffer_write_u16(buf, e->flags);
		sldns_buffer_write_u16(buf, e->code);
		/* copy str without \0 */

		if(e->extra_text) {
			extratextlen = strlen(e->extra_text);
			sldns_buffer_write(buf, e->extra_text,
				extratextlen * sizeof(char));
		}
		e = e->next;

		/* add option to edns opts list */
		edns_opt_list_append(&edns_out->opt_list,
			EE_OPT_CODE, 4 + extratextlen,
			sldns_buffer_begin(buf), region);
	}
	sldns_buffer_free(buf);
	return 1;
}
